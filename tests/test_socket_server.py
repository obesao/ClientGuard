"""Testa os comandos do socket (_cmd_*) chamando SocketServer.dispatch diretamente,
sem abrir um socket Unix de verdade — SocketServer.__init__ faria bind/chmod num
arquivo real, desnecessário pra testar só a lógica de despacho dos comandos.

Cobre tanto os comandos novos de mitigação de borda (edge_*) quanto block_*/toggles,
que não tinham nenhum teste automatizado antes desta suíte existir."""

from __future__ import annotations

import threading
from unittest.mock import MagicMock, patch

import pytest

import configio
import edge_mitigation
import flowspec_mitigation
import socket_server
import storage


class FakeDaemon:
    def __init__(self, conn, tmp_path):
        self.conn = conn
        self.db_lock = threading.Lock()
        self.total_rows = 0
        self.started_at = 0
        self.customers = []
        self.whitelist = []
        self.config = {
            "daemon": {"socket": "/tmp/nao-usado.sock"},
            "flowguard_socket": "/var/run/flowguard.sock",
            "flowguard_reuse": {"path": str(tmp_path / "flowguard")},
            "edge_mitigation_file": str(tmp_path / "edge_mitigation.yaml"),
            "customer_registry": str(tmp_path / "customers.yaml"),
            "detection_templates_file": str(tmp_path / "detection_templates.yaml"),
            "detection_overrides_file": str(tmp_path / "detection_overrides.yaml"),
            "database": {"aggregate_interval_s": 30, "path": str(tmp_path / "client_flow.sqlite")},
            "capture": {"iface": "ens18", "bpf_filter": "udp port 2055"},
            "detection": {"scan_horizontal_hosts": 50, "scan_vertical_ports": 150},
        }
        self.edge_cfg = edge_mitigation.load_config(self.config["edge_mitigation_file"])
        self.edge_cfg["warmode_device"] = "NE8000 borda"
        self.flowspec_mitigation_cfg = flowspec_mitigation.load_config(
            str(tmp_path / "flowspec_mitigation.yaml"))
        self.detection_templates = configio.load_detection_templates(self.config["detection_templates_file"])
        self._detection_base = dict(self.config["detection"])
        self.toggles = {}
        self.reload_calls = 0

    def reload_config(self):
        self.reload_calls += 1
        self.edge_cfg = edge_mitigation.load_config(self.config["edge_mitigation_file"])
        self.detection_templates = configio.load_detection_templates(self.config["detection_templates_file"])
        self.config["detection"] = {
            **self._detection_base,
            **configio.load_detection_overrides(self.config["detection_overrides_file"]),
        }


def _write_warmode_yaml(tmp_path):
    flowguard_dir = tmp_path / "flowguard"
    flowguard_dir.mkdir()
    (flowguard_dir / "warmode.yaml").write_text(
        "devices:\n  - name: \"NE8000 borda\"\n    host: 10.0.0.1\n    port: 22\n"
        "    device_type: huawei_vrp\n    username: admin\n    password: secret\n"
        "    enable_mode: false\n",
        encoding="utf-8",
    )


@pytest.fixture
def conn(tmp_path):
    # arquivo real (não :memory:) — os comandos de leitura do socket agora abrem
    # uma segunda conexão read-only pro mesmo arquivo (ver socket_server._read_only_conn),
    # o que :memory: não permite (cada conexão em memória é isolada).
    c = storage.connect(str(tmp_path / "client_flow.sqlite"), check_same_thread=False)
    yield c
    c.close()


@pytest.fixture
def server(conn, tmp_path):
    _write_warmode_yaml(tmp_path)
    srv = socket_server.SocketServer.__new__(socket_server.SocketServer)
    srv.daemon_ref = FakeDaemon(conn, tmp_path)
    return srv


# --- block_* (proxy pro FlowGuard) ----------------------------------------

def test_block_add_sends_flowspec_discard_rule(server):
    with patch("control.send_command", return_value={"ok": True, "rule_id": 1}) as mock_send:
        resp = server.dispatch({"cmd": "block_add", "ip": "1.2.3.4"})
    assert resp == {"ok": True, "rule_id": 1}
    sock_path, payload = mock_send.call_args[0]
    assert sock_path == "/var/run/flowguard.sock"
    assert payload["cmd"] == "flowspec_add"
    assert payload["rule"]["src_prefix"] == "1.2.3.4/32"
    assert payload["rule"]["action"] == "discard"
    assert payload["origin"] == "clientguard"  # aba Regras unificada do portal separa por aplicação
    assert payload["peer"] == "pppoe"  # achado real: sem isso caía no peer 'main', que nunca vê o cliente


def test_block_add_missing_ip(server):
    resp = server.dispatch({"cmd": "block_add"})
    assert resp["ok"] is False


def test_block_add_invalid_ip(server):
    resp = server.dispatch({"cmd": "block_add", "ip": "não-é-um-ip"})
    assert resp["ok"] is False


def test_block_add_pushes_pbr_bypass_when_enabled(server):
    # achado real: o bloqueio manual nunca acionava a exceção de PBR — só a
    # mitigação automática dos detectores era coberta.
    server.daemon_ref.flowspec_mitigation_cfg["pbr_bypass"] = {
        "enabled": True, "warmode_device": "NE8000 borda", "acl_number": 3001, "rule_id_base": 50000,
    }
    fake_conn = MagicMock()
    fake_conn.send_config_set.return_value = "ok"
    with patch("control.send_command", return_value={"ok": True, "rule_id": 7}), \
         patch("netmiko.ConnectHandler", return_value=fake_conn) as mock_handler:
        resp = server.dispatch({"cmd": "block_add", "ip": "1.2.3.4"})
    assert resp["ok"] is True
    mock_handler.assert_called_once()
    sent = fake_conn.send_config_set.call_args[0][0]
    assert sent == ["acl number 3001", "rule 50007 permit ip source 1.2.3.4 0", "quit", "commit"]


def test_block_add_reports_pbr_bypass_failure(server):
    server.daemon_ref.flowspec_mitigation_cfg["pbr_bypass"] = {
        "enabled": True, "warmode_device": "NE8000 borda", "acl_number": 3001, "rule_id_base": 50000,
    }
    with patch("control.send_command", return_value={"ok": True, "rule_id": 7}), \
         patch("netmiko.ConnectHandler", side_effect=OSError("conexão recusada")):
        resp = server.dispatch({"cmd": "block_add", "ip": "1.2.3.4"})
    assert resp["ok"] is True  # FlowSpec em si foi anunciado com sucesso
    assert "pbr_bypass_error" in resp


def test_block_del_sends_flowspec_del(server):
    with patch("control.send_command", return_value={"ok": True}) as mock_send:
        resp = server.dispatch({"cmd": "block_del", "id": 7})
    assert resp["ok"] is True
    _, payload = mock_send.call_args[0]
    assert payload == {"cmd": "flowspec_del", "rule_id": 7}


def test_block_del_removes_pbr_bypass_when_enabled(server):
    server.daemon_ref.flowspec_mitigation_cfg["pbr_bypass"] = {
        "enabled": True, "warmode_device": "NE8000 borda", "acl_number": 3001, "rule_id_base": 50000,
    }
    fake_conn = MagicMock()
    fake_conn.send_config_set.return_value = "ok"
    with patch("control.send_command", return_value={"ok": True}), \
         patch("netmiko.ConnectHandler", return_value=fake_conn) as mock_handler:
        resp = server.dispatch({"cmd": "block_del", "id": 7})
    assert resp["ok"] is True
    mock_handler.assert_called_once()
    sent = fake_conn.send_config_set.call_args[0][0]
    assert sent == ["acl number 3001", "undo rule 50007", "quit", "commit"]


def test_block_list_filters_out_rtbh(server):
    rules = [
        {"id": 1, "src_prefix": "1.2.3.4/32", "action": "discard", "origin": "clientguard"},
        {"id": 2, "src_prefix": None, "action": "rtbh", "origin": "clientguard"},
        {"id": 3, "src_prefix": "5.6.7.8/32", "action": "rtbh", "origin": "clientguard"},
    ]
    with patch("control.send_command", return_value={"ok": True, "rules": rules}):
        resp = server.dispatch({"cmd": "block_list"})
    assert resp["ok"] is True
    assert [b["id"] for b in resp["blocks"]] == [1]


def test_block_list_filters_out_other_origins(server):
    # bug real: sem filtrar por origin, bloqueios manuais do FlowGuard e
    # mitigações automáticas do próprio ClientGuard (que não são "bloqueio
    # manual de cliente") apareciam juntos nesta lista.
    rules = [
        {"id": 1, "src_prefix": "1.2.3.4/32", "action": "discard", "origin": "clientguard"},
        {"id": 2, "src_prefix": "9.9.9.9/32", "action": "discard", "origin": "flowguard"},
        {"id": 3, "src_prefix": "8.8.8.8/32", "action": "discard"},
    ]
    with patch("control.send_command", return_value={"ok": True, "rules": rules}):
        resp = server.dispatch({"cmd": "block_list"})
    assert resp["ok"] is True
    assert [b["id"] for b in resp["blocks"]] == [1]


# --- edge_* (SSH/ACL direto na borda) --------------------------------------

def test_edge_apply_creates_active_mitigation(server, conn):
    fake_conn = MagicMock()
    fake_conn.send_config_set.return_value = "ok"
    with patch("netmiko.ConnectHandler", return_value=fake_conn):
        resp = server.dispatch({"cmd": "edge_apply", "ip": "1.2.3.4"})
    assert resp["ok"] is True
    row = storage.get_active_edge_mitigation(conn, "1.2.3.4")
    assert row is not None
    assert row["trigger_type"] == "manual"


def test_edge_apply_missing_ip(server):
    resp = server.dispatch({"cmd": "edge_apply"})
    assert resp["ok"] is False


def test_edge_apply_uses_default_ttl_when_not_given(server, conn):
    fake_conn = MagicMock()
    fake_conn.send_config_set.return_value = "ok"
    with patch("netmiko.ConnectHandler", return_value=fake_conn):
        server.dispatch({"cmd": "edge_apply", "ip": "1.2.3.4"})
    row = storage.get_active_edge_mitigation(conn, "1.2.3.4")
    assert row["ts_expires"] is not None


def test_edge_revert_marks_reverted(server, conn):
    mitigation_id = storage.insert_edge_mitigation(conn, "1.2.3.4", None, 3600, "manual")
    fake_conn = MagicMock()
    fake_conn.send_config_set.return_value = "ok"
    with patch("netmiko.ConnectHandler", return_value=fake_conn):
        resp = server.dispatch({"cmd": "edge_revert", "id": mitigation_id})
    assert resp["ok"] is True
    assert storage.get_edge_mitigation(conn, mitigation_id)["status"] == "reverted"


def test_edge_revert_missing_id(server):
    resp = server.dispatch({"cmd": "edge_revert"})
    assert resp["ok"] is False


def test_edge_revert_dispatches_flowspec_mechanism_to_flowspec_del(server, conn):
    # achado real: revert de uma linha mechanism='flowspec' caía sempre no caminho
    # SSH/ACL legado (edge_mitigation.revert_and_record) — a regra FlowSpec de
    # verdade nunca era retirada do FlowGuard, só ficava "reverted"/"failed" no
    # lado do ClientGuard enquanto continuava ativa no roteador até o próprio TTL
    # vencer. Preciso confirmar que o despacho vai pro módulo certo, sem tocar SSH.
    mitigation_id = storage.insert_edge_mitigation(
        conn, "1.2.3.4", None, 3600, "manual", mechanism="flowspec", flowspec_rule_id=42,
    )
    with patch("control.send_command", return_value={"ok": True}) as mock_send, \
         patch("netmiko.ConnectHandler") as mock_ssh:
        resp = server.dispatch({"cmd": "edge_revert", "id": mitigation_id})
    assert resp["ok"] is True
    _, payload = mock_send.call_args[0]
    assert payload == {"cmd": "flowspec_del", "rule_id": 42}
    assert not mock_ssh.called
    assert storage.get_edge_mitigation(conn, mitigation_id)["status"] == "reverted"


def test_edge_revert_unknown_id(server):
    resp = server.dispatch({"cmd": "edge_revert", "id": 999})
    assert resp["ok"] is False


def test_edge_revert_all_reverts_mixed_mechanisms(server, conn):
    ssh_id = storage.insert_edge_mitigation(conn, "1.2.3.4", None, 3600, "manual")
    flowspec_id = storage.insert_edge_mitigation(
        conn, "5.6.7.8", None, 3600, "manual", mechanism="flowspec", flowspec_rule_id=7,
    )
    inactive_id = storage.insert_edge_mitigation(conn, "9.9.9.9", None, 3600, "manual")
    storage.mark_edge_reverted(conn, inactive_id)

    fake_conn = MagicMock()
    fake_conn.send_config_set.return_value = "ok"
    with patch("netmiko.ConnectHandler", return_value=fake_conn), \
         patch("control.send_command", return_value={"ok": True}) as mock_send:
        resp = server.dispatch({"cmd": "edge_revert_all"})

    assert resp == {"ok": True, "reverted": 2, "failed": 0}
    assert storage.get_edge_mitigation(conn, ssh_id)["status"] == "reverted"
    assert storage.get_edge_mitigation(conn, flowspec_id)["status"] == "reverted"
    _, payload = mock_send.call_args[0]
    assert payload == {"cmd": "flowspec_del", "rule_id": 7}
    # a já inativa não é tocada de novo (list_edge_mitigations active_only exclui ela)
    assert storage.get_edge_mitigation(conn, inactive_id)["ts_reverted"] is not None


def test_edge_revert_all_counts_failures(server, conn):
    storage.insert_edge_mitigation(
        conn, "5.6.7.8", None, 3600, "manual", mechanism="flowspec", flowspec_rule_id=7,
    )
    with patch("control.send_command", return_value={"ok": False, "error": "timeout"}):
        resp = server.dispatch({"cmd": "edge_revert_all"})
    assert resp == {"ok": False, "reverted": 0, "failed": 1}


def test_edge_revert_all_no_active_mitigations(server):
    resp = server.dispatch({"cmd": "edge_revert_all"})
    assert resp == {"ok": True, "reverted": 0, "failed": 0}


def test_edge_list_returns_all_by_default(server, conn):
    storage.insert_edge_mitigation(conn, "1.2.3.4", None, 3600, "manual")
    storage.mark_edge_reverted(conn, storage.insert_edge_mitigation(conn, "5.6.7.8", None, 3600, "manual"))
    resp = server.dispatch({"cmd": "edge_list"})
    assert resp["ok"] is True
    assert len(resp["mitigations"]) == 2


def test_edge_list_active_only(server, conn):
    storage.insert_edge_mitigation(conn, "1.2.3.4", None, 3600, "manual")
    storage.mark_edge_reverted(conn, storage.insert_edge_mitigation(conn, "5.6.7.8", None, 3600, "manual"))
    resp = server.dispatch({"cmd": "edge_list", "active_only": True})
    assert resp["ok"] is True
    assert len(resp["mitigations"]) == 1
    assert resp["mitigations"][0]["src_ip"] == "1.2.3.4"


# --- edge_list: device_name (pedido do usuário — em qual equipamento) ------

def test_edge_list_ssh_mechanism_uses_warmode_device(server, conn):
    storage.insert_edge_mitigation(conn, "1.2.3.4", None, 3600, "manual", mechanism="ssh")
    resp = server.dispatch({"cmd": "edge_list"})
    assert resp["mitigations"][0]["device_name"] == server.daemon_ref.edge_cfg["warmode_device"]


def test_edge_list_flowspec_mechanism_uses_pbr_bypass_device(server, conn):
    server.daemon_ref.flowspec_mitigation_cfg["pbr_bypass"] = {"warmode_device": "HUAWEI-PPPOE-222"}
    storage.insert_edge_mitigation(conn, "1.2.3.4", None, 3600, "auto", mechanism="flowspec", flowspec_rule_id=1)
    resp = server.dispatch({"cmd": "edge_list"})
    assert resp["mitigations"][0]["device_name"] == "HUAWEI-PPPOE-222"


def test_edge_list_flowspec_device_name_falls_back_to_pppoe_when_unconfigured(server, conn):
    server.daemon_ref.flowspec_mitigation_cfg["pbr_bypass"] = {}  # sem warmode_device
    storage.insert_edge_mitigation(conn, "1.2.3.4", None, 3600, "auto", mechanism="flowspec", flowspec_rule_id=1)
    resp = server.dispatch({"cmd": "edge_list"})
    assert resp["mitigations"][0]["device_name"] == "pppoe"


def test_edge_config_never_exposes_credentials(server):
    resp = server.dispatch({"cmd": "edge_config"})
    assert resp["ok"] is True
    assert "password" not in resp["config"]
    assert resp["config"]["warmode_device"] == "NE8000 borda"
    assert resp["config"]["auto_mitigate"]["spam_bot"] is False


def test_edge_set_auto_updates_config_and_reloads(server, tmp_path):
    resp = server.dispatch({"cmd": "edge_set_auto", "auto_mitigate": {"spam_bot": True}})
    assert resp["ok"] is True
    assert resp["config"]["auto_mitigate"]["spam_bot"] is True
    assert server.daemon_ref.reload_calls == 1
    reloaded = edge_mitigation.load_config(server.daemon_ref.config["edge_mitigation_file"])
    assert reloaded["auto_mitigate"]["spam_bot"] is True


def test_edge_set_auto_unknown_detector_rejected(server):
    resp = server.dispatch({"cmd": "edge_set_auto", "auto_mitigate": {"nao_existe": True}})
    assert resp["ok"] is False
    assert server.daemon_ref.reload_calls == 0


def test_edge_set_auto_requires_nonempty_dict(server):
    resp = server.dispatch({"cmd": "edge_set_auto", "auto_mitigate": {}})
    assert resp["ok"] is False


def test_status_reports_total_rows_from_memory_not_a_query(server):
    # total_rows vem de d.total_rows (contador incremental no daemon), não de um
    # COUNT(*) na hora — achado real: COUNT(*) sem WHERE em client_flow_aggs virou
    # uma varredura de tabela inteira (~2.5s sob ~26M linhas) chamada a cada poll
    # de status do portal.
    server.daemon_ref.total_rows = 12345
    resp = server.dispatch({"cmd": "status"})
    assert resp["ok"] is True
    assert resp["total_rows"] == 12345


def test_dispatch_unknown_command(server):
    resp = server.dispatch({"cmd": "isso_nao_existe"})
    assert resp["ok"] is False


# --- suspicious: sinaliza se o cliente já participa de alguma mitigação -----
# (pedido do usuário: aba Sinais Suspeitos do portal precisa mostrar se aquele
# src_ip já está/esteve numa regra de mitigação, e se ainda está em vigor)

def test_suspicious_reports_no_mitigation_when_never_mitigated(server, conn):
    storage.insert_suspicious_client(conn, {"src_ip": "1.2.3.4", "signal_type": "port_scan_horizontal"})
    resp = server.dispatch({"cmd": "suspicious"})
    assert resp["ok"] is True
    assert resp["suspicious"][0]["mitigation"] is None


def test_suspicious_reports_active_mitigation(server, conn):
    storage.insert_suspicious_client(conn, {"src_ip": "1.2.3.4", "signal_type": "port_scan_horizontal"})
    storage.insert_edge_mitigation(conn, "1.2.3.4", None, 3600, "auto",
                                    mechanism="flowspec", flowspec_rule_id=42)
    resp = server.dispatch({"cmd": "suspicious"})
    mitigation = resp["suspicious"][0]["mitigation"]
    assert mitigation["status"] == "active"
    assert mitigation["mechanism"] == "flowspec"
    assert mitigation["trigger_type"] == "auto"


def test_suspicious_reports_latest_mitigation_even_when_reverted(server, conn):
    # achado real de auditoria: um cliente pode ter sido mitigado e a regra ter
    # saído do ar (TTL, ou reconciliação achando que sumiu do FlowGuard) — a aba
    # precisa mostrar "já foi mitigado, mas não está mais em vigor", não "nunca
    # foi mitigado" (get_latest_edge_mitigation, não get_active_edge_mitigation).
    storage.insert_suspicious_client(conn, {"src_ip": "1.2.3.4", "signal_type": "port_scan_horizontal"})
    mitigation_id = storage.insert_edge_mitigation(conn, "1.2.3.4", None, 3600, "auto",
                                                     mechanism="flowspec", flowspec_rule_id=42)
    storage.mark_edge_reverted(conn, mitigation_id)
    resp = server.dispatch({"cmd": "suspicious"})
    mitigation = resp["suspicious"][0]["mitigation"]
    assert mitigation["status"] == "reverted"


def test_suspicious_only_matches_mitigation_by_same_src_ip(server, conn):
    storage.insert_suspicious_client(conn, {"src_ip": "1.2.3.4", "signal_type": "port_scan_horizontal"})
    storage.insert_edge_mitigation(conn, "5.6.7.8", None, 3600, "auto",
                                    mechanism="flowspec", flowspec_rule_id=42)
    resp = server.dispatch({"cmd": "suspicious"})
    assert resp["suspicious"][0]["mitigation"] is None


# --- ajuste fino dos limiares de detecção (config.yaml::detection) ------------

def test_detection_cfg_returns_effective_values(server):
    resp = server.dispatch({"cmd": "detection_cfg"})
    assert resp == {"ok": True, "detection": {"scan_horizontal_hosts": 50, "scan_vertical_ports": 150}}


def test_detection_cfg_set_applies_override_and_reloads(server):
    resp = server.dispatch({"cmd": "detection_cfg_set", "changes": {"scan_horizontal_hosts": 80}})
    assert resp["ok"] is True
    assert resp["detection"]["scan_horizontal_hosts"] == 80
    assert resp["detection"]["scan_vertical_ports"] == 150  # não mexido, continua o global
    assert server.daemon_ref.reload_calls == 1


def test_detection_cfg_set_requires_non_empty_changes(server):
    resp = server.dispatch({"cmd": "detection_cfg_set", "changes": {}})
    assert resp["ok"] is False


def test_detection_cfg_set_rejects_unknown_key(server):
    resp = server.dispatch({"cmd": "detection_cfg_set", "changes": {"nao_existe": 1}})
    assert resp["ok"] is False
    assert server.daemon_ref.reload_calls == 0  # falhou antes de aplicar, não recarrega à toa


def test_detection_cfg_set_persists_across_dispatches(server):
    server.dispatch({"cmd": "detection_cfg_set", "changes": {"scan_horizontal_hosts": 80}})
    resp = server.dispatch({"cmd": "detection_cfg"})
    assert resp["detection"]["scan_horizontal_hosts"] == 80


# --- templates de perfil de rede (detection_templates.yaml) -------------------

def test_detection_templates_empty_by_default(server):
    resp = server.dispatch({"cmd": "detection_templates"})
    assert resp == {"ok": True, "templates": {}}


def test_detection_templates_set_creates_and_reloads(server):
    resp = server.dispatch({
        "cmd": "detection_templates_set", "name": "cgnat",
        "values": {"scan_horizontal_hosts": 250, "scan_vertical_ports": 300},
        "description": "pool CGNAT",
    })
    assert resp["ok"] is True
    assert resp["templates"]["cgnat"]["scan_horizontal_hosts"] == 250
    assert server.daemon_ref.reload_calls == 1
    assert server.daemon_ref.detection_templates["cgnat"]["scan_horizontal_hosts"] == 250


def test_detection_templates_set_rejects_bad_values(server):
    resp = server.dispatch({
        "cmd": "detection_templates_set", "name": "cgnat", "values": {"scan_horizontal_hosts": -1},
    })
    assert resp["ok"] is False


def test_detection_templates_del_removes_and_reloads(server):
    server.dispatch({"cmd": "detection_templates_set", "name": "cgnat", "values": {"scan_horizontal_hosts": 250}})
    resp = server.dispatch({"cmd": "detection_templates_del", "name": "cgnat"})
    assert resp["ok"] is True
    assert "cgnat" not in resp["templates"]
    assert "cgnat" not in server.daemon_ref.detection_templates


def test_detection_templates_del_unknown_fails(server):
    resp = server.dispatch({"cmd": "detection_templates_del", "name": "nao_existe"})
    assert resp["ok"] is False


# --- customers_add/customers_edit com template/client_multiplier ---------------

def test_customers_add_with_template_and_multiplier(server):
    server.dispatch({"cmd": "detection_templates_set", "name": "cgnat", "values": {"scan_horizontal_hosts": 250}})
    resp = server.dispatch({
        "cmd": "customers_add", "network": "100.64.0.0/10", "prefix": "100.64.0.0/10",
        "template": "cgnat", "client_multiplier": 4,
    })
    assert resp["ok"] is True
    items = configio.load_yaml_list(server.daemon_ref.config["customer_registry"])
    assert items[0]["template"] == "cgnat"
    assert items[0]["client_multiplier"] == 4


def test_customers_add_rejects_unknown_template(server):
    resp = server.dispatch({
        "cmd": "customers_add", "network": "100.64.0.0/10", "prefix": "100.64.0.0/10", "template": "nao_existe",
    })
    assert resp["ok"] is False


def test_customers_edit_sets_template_on_existing_entry(server):
    server.dispatch({"cmd": "customers_add", "network": "177.86.20.0/24", "prefix": "177.86.20.0/24"})
    server.dispatch({"cmd": "detection_templates_set", "name": "cgnat", "values": {"scan_horizontal_hosts": 250}})
    resp = server.dispatch({"cmd": "customers_edit", "network": "177.86.20.0/24", "template": "cgnat"})
    assert resp["ok"] is True
    assert resp["entry"]["template"] == "cgnat"


def test_customers_edit_clears_template_with_empty_value(server):
    server.dispatch({"cmd": "detection_templates_set", "name": "cgnat", "values": {"scan_horizontal_hosts": 250}})
    server.dispatch({
        "cmd": "customers_add", "network": "177.86.20.0/24", "prefix": "177.86.20.0/24", "template": "cgnat",
    })
    resp = server.dispatch({"cmd": "customers_edit", "network": "177.86.20.0/24", "template": ""})
    assert resp["ok"] is True
    assert "template" not in resp["entry"]


def test_customers_edit_unknown_network_fails(server):
    resp = server.dispatch({"cmd": "customers_edit", "network": "9.9.9.0/24", "template": "cgnat"})
    assert resp["ok"] is False
