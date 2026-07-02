"""Testa edge_mitigation — mocka Netmiko (nunca conecta de verdade via rede)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

import edge_mitigation
import storage


def _write_warmode_yaml(tmp_path, device_name="NE8000 borda", **overrides):
    device = {
        "name": device_name, "host": "10.0.0.1", "port": 22, "device_type": "huawei_vrp",
        "username": "admin", "password": "secret", "enable_mode": False,
    }
    device.update(overrides)
    flowguard_dir = tmp_path / "flowguard"
    flowguard_dir.mkdir()
    (flowguard_dir / "warmode.yaml").write_text(
        f"devices:\n  - name: \"{device['name']}\"\n    host: {device['host']}\n"
        f"    port: {device['port']}\n    device_type: {device['device_type']}\n"
        f"    username: {device['username']}\n    password: {device['password']}\n"
        f"    enable_mode: {str(device['enable_mode']).lower()}\n",
        encoding="utf-8",
    )
    return str(flowguard_dir)


def _cfg(**overrides):
    cfg = edge_mitigation.load_config("/caminho/que/nao/existe.yaml")  # cai no DEFAULT_CONFIG
    cfg["warmode_device"] = "NE8000 borda"
    cfg.update(overrides)
    return cfg


@pytest.fixture
def conn():
    c = storage.connect(":memory:", check_same_thread=False)
    yield c
    c.close()


# --- load_config / save_auto_mitigate -------------------------------------

def test_load_config_missing_file_returns_defaults(tmp_path):
    cfg = edge_mitigation.load_config(str(tmp_path / "nao-existe.yaml"))
    assert cfg["acl_number"] == edge_mitigation.DEFAULT_CONFIG["acl_number"]
    assert all(v is False for v in cfg["auto_mitigate"].values())


def test_save_auto_mitigate_roundtrip(tmp_path):
    path = tmp_path / "edge_mitigation.yaml"
    updated = edge_mitigation.save_auto_mitigate({"spam_bot": True}, path=str(path))
    assert updated["auto_mitigate"]["spam_bot"] is True
    reloaded = edge_mitigation.load_config(str(path))
    assert reloaded["auto_mitigate"]["spam_bot"] is True
    assert reloaded["auto_mitigate"]["port_scan_horizontal"] is False  # não tocado


def test_save_auto_mitigate_updates_ttl(tmp_path):
    path = tmp_path / "edge_mitigation.yaml"
    updated = edge_mitigation.save_auto_mitigate({}, default_ttl_s=3600, path=str(path))
    assert updated["default_ttl_s"] == 3600


def test_save_auto_mitigate_unknown_key_raises(tmp_path):
    path = tmp_path / "edge_mitigation.yaml"
    with pytest.raises(ValueError):
        edge_mitigation.save_auto_mitigate({"nao_existe": True}, path=str(path))
    assert not path.exists()


def test_save_auto_mitigate_preserves_acl_number_and_commands(tmp_path):
    path = tmp_path / "edge_mitigation.yaml"
    edge_mitigation.save_auto_mitigate({}, path=str(path))
    reloaded = edge_mitigation.load_config(str(path))
    assert reloaded["acl_number"] == edge_mitigation.DEFAULT_CONFIG["acl_number"]
    assert reloaded["apply_commands"] == edge_mitigation.DEFAULT_CONFIG["apply_commands"]


# --- apply_block / revert_block (Netmiko mockado) -------------------------

def test_apply_block_success(tmp_path):
    flowguard_path = _write_warmode_yaml(tmp_path)
    cfg = _cfg()
    fake_conn = MagicMock()
    fake_conn.send_config_set.return_value = "ok"
    with patch("netmiko.ConnectHandler", return_value=fake_conn) as mock_handler:
        result = edge_mitigation.apply_block("1.2.3.4", cfg, flowguard_path)
    assert result["ok"] is True
    mock_handler.assert_called_once()
    sent_commands = fake_conn.send_config_set.call_args[0][0]
    assert sent_commands == ["acl number 3999", "rule deny ip source 1.2.3.4 0"]
    fake_conn.disconnect.assert_called_once()


def test_revert_block_success(tmp_path):
    flowguard_path = _write_warmode_yaml(tmp_path)
    cfg = _cfg()
    fake_conn = MagicMock()
    fake_conn.send_config_set.return_value = "ok"
    with patch("netmiko.ConnectHandler", return_value=fake_conn):
        result = edge_mitigation.revert_block("1.2.3.4", cfg, flowguard_path)
    assert result["ok"] is True
    sent_commands = fake_conn.send_config_set.call_args[0][0]
    assert sent_commands == ["acl number 3999", "undo rule deny ip source 1.2.3.4 0"]


def test_apply_block_device_not_found_in_warmode_yaml(tmp_path):
    flowguard_path = _write_warmode_yaml(tmp_path, device_name="Outro Equipamento")
    cfg = _cfg()  # cfg["warmode_device"] = "NE8000 borda", não existe no warmode.yaml
    result = edge_mitigation.apply_block("1.2.3.4", cfg, flowguard_path)
    assert result["ok"] is False
    assert "não encontrado" in result["error"]


def test_apply_block_missing_warmode_device_config(tmp_path):
    flowguard_path = _write_warmode_yaml(tmp_path)
    cfg = _cfg(warmode_device="")
    result = edge_mitigation.apply_block("1.2.3.4", cfg, flowguard_path)
    assert result["ok"] is False
    assert "warmode_device" in result["error"]


def test_apply_block_authentication_failure(tmp_path):
    from netmiko.exceptions import NetmikoAuthenticationException

    flowguard_path = _write_warmode_yaml(tmp_path)
    cfg = _cfg()
    with patch("netmiko.ConnectHandler", side_effect=NetmikoAuthenticationException("boom")):
        result = edge_mitigation.apply_block("1.2.3.4", cfg, flowguard_path)
    assert result["ok"] is False
    assert "autenticação" in result["error"]


def test_apply_block_writes_audit_log(tmp_path, monkeypatch):
    flowguard_path = _write_warmode_yaml(tmp_path)
    cfg = _cfg()
    audit_path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(edge_mitigation, "AUDIT_LOG_PATH", str(audit_path))
    fake_conn = MagicMock()
    fake_conn.send_config_set.return_value = "ok"
    with patch("netmiko.ConnectHandler", return_value=fake_conn):
        edge_mitigation.apply_block("1.2.3.4", cfg, flowguard_path)
    assert audit_path.exists()
    assert "1.2.3.4" in audit_path.read_text(encoding="utf-8")


# --- apply_and_record / revert_and_record / expire_due (storage + executor) --

def test_apply_and_record_inserts_row_and_calls_ssh(conn, tmp_path):
    flowguard_path = _write_warmode_yaml(tmp_path)
    cfg = _cfg()
    fake_conn = MagicMock()
    fake_conn.send_config_set.return_value = "ok"
    with patch("netmiko.ConnectHandler", return_value=fake_conn):
        result = edge_mitigation.apply_and_record(conn, None, "1.2.3.4", None, 3600, "manual", cfg, flowguard_path)
    assert result["ok"] is True
    row = storage.get_active_edge_mitigation(conn, "1.2.3.4")
    assert row is not None
    assert row["trigger_type"] == "manual"


def test_apply_and_record_idempotent_extends_ttl_without_reapplying(conn, tmp_path):
    flowguard_path = _write_warmode_yaml(tmp_path)
    cfg = _cfg()
    fake_conn = MagicMock()
    fake_conn.send_config_set.return_value = "ok"
    with patch("netmiko.ConnectHandler", return_value=fake_conn) as mock_handler:
        edge_mitigation.apply_and_record(conn, None, "1.2.3.4", None, 3600, "manual", cfg, flowguard_path)
        result = edge_mitigation.apply_and_record(conn, None, "1.2.3.4", None, 7200, "manual", cfg, flowguard_path)
    assert result["ok"] is True
    assert result["already_active"] is True
    mock_handler.assert_called_once()  # segunda chamada NÃO conecta de novo


def test_apply_and_record_failure_does_not_insert_row(conn, tmp_path):
    flowguard_path = _write_warmode_yaml(tmp_path, device_name="Outro")
    cfg = _cfg()
    result = edge_mitigation.apply_and_record(conn, None, "1.2.3.4", None, 3600, "manual", cfg, flowguard_path)
    assert result["ok"] is False
    assert storage.get_active_edge_mitigation(conn, "1.2.3.4") is None


def test_revert_and_record_marks_reverted(conn, tmp_path):
    flowguard_path = _write_warmode_yaml(tmp_path)
    cfg = _cfg()
    mitigation_id = storage.insert_edge_mitigation(conn, "1.2.3.4", None, 3600, "manual")
    fake_conn = MagicMock()
    fake_conn.send_config_set.return_value = "ok"
    with patch("netmiko.ConnectHandler", return_value=fake_conn):
        result = edge_mitigation.revert_and_record(conn, None, mitigation_id, cfg, flowguard_path)
    assert result["ok"] is True
    row = storage.get_edge_mitigation(conn, mitigation_id)
    assert row["status"] == "reverted"


def test_revert_and_record_unknown_id(conn, tmp_path):
    flowguard_path = _write_warmode_yaml(tmp_path)
    cfg = _cfg()
    result = edge_mitigation.revert_and_record(conn, None, 999, cfg, flowguard_path)
    assert result["ok"] is False


def test_expire_due_reverts_only_expired(conn, tmp_path):
    flowguard_path = _write_warmode_yaml(tmp_path)
    cfg = _cfg()
    expired_id = storage.insert_edge_mitigation(conn, "1.2.3.4", None, -10, "manual")  # já vencido
    active_id = storage.insert_edge_mitigation(conn, "5.6.7.8", None, 3600, "manual")  # ainda válido
    fake_conn = MagicMock()
    fake_conn.send_config_set.return_value = "ok"
    with patch("netmiko.ConnectHandler", return_value=fake_conn):
        count = edge_mitigation.expire_due(conn, None, cfg, flowguard_path)
    assert count == 1
    assert storage.get_edge_mitigation(conn, expired_id)["status"] == "reverted"
    assert storage.get_edge_mitigation(conn, active_id)["status"] == "active"
