"""Testa os comandos do socket (_cmd_*) chamando SocketServer.dispatch diretamente,
sem abrir um socket Unix de verdade — SocketServer.__init__ faria bind/chmod num
arquivo real, desnecessário pra testar só a lógica de despacho dos comandos.

Cobre tanto os comandos novos de mitigação de borda (edge_*) quanto block_*/toggles,
que não tinham nenhum teste automatizado antes desta suíte existir."""

from __future__ import annotations

import threading
from unittest.mock import MagicMock, patch

import pytest

import edge_mitigation
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
            "database": {"aggregate_interval_s": 30, "path": str(tmp_path / "client_flow.sqlite")},
            "capture": {"iface": "ens18", "bpf_filter": "udp port 2055"},
        }
        self.edge_cfg = edge_mitigation.load_config(self.config["edge_mitigation_file"])
        self.edge_cfg["warmode_device"] = "NE8000 borda"
        self.toggles = {}
        self.reload_calls = 0

    def reload_config(self):
        self.reload_calls += 1
        self.edge_cfg = edge_mitigation.load_config(self.config["edge_mitigation_file"])


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


def test_block_add_missing_ip(server):
    resp = server.dispatch({"cmd": "block_add"})
    assert resp["ok"] is False


def test_block_add_invalid_ip(server):
    resp = server.dispatch({"cmd": "block_add", "ip": "não-é-um-ip"})
    assert resp["ok"] is False


def test_block_del_sends_flowspec_del(server):
    with patch("control.send_command", return_value={"ok": True}) as mock_send:
        resp = server.dispatch({"cmd": "block_del", "id": 7})
    assert resp["ok"] is True
    _, payload = mock_send.call_args[0]
    assert payload == {"cmd": "flowspec_del", "rule_id": 7}


def test_block_list_filters_out_rtbh(server):
    rules = [
        {"id": 1, "src_prefix": "1.2.3.4/32", "action": "discard"},
        {"id": 2, "src_prefix": None, "action": "rtbh"},
        {"id": 3, "src_prefix": "5.6.7.8/32", "action": "rtbh"},
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
