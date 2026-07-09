"""Testa escalation.py — bloqueio progressivo por reincidência (estilo fail2ban).
offense_no vem de storage.count_recent_mitigations (histórico de edge_mitigations,
nunca deletado) — aqui simulado inserindo linhas direto via storage.insert_edge_mitigation."""

from __future__ import annotations

import time

import pytest

import escalation
import storage


def _cfg(**overrides):
    cfg = dict(escalation.DEFAULT_CONFIG)
    cfg.update(overrides)
    return cfg


def _add_offense(conn, src_ip, ts_ago=0, mechanism="flowspec"):
    mid = storage.insert_edge_mitigation(conn, src_ip, None, 3600, "auto", mechanism=mechanism)
    if ts_ago:
        conn.execute("UPDATE edge_mitigations SET ts_applied = ? WHERE id = ?",
                     (int(time.time()) - ts_ago, mid))
        conn.commit()
    return mid


def test_next_ttl_s_no_history_uses_base(conn):
    cfg = _cfg(base_ttl_s=None)
    assert escalation.next_ttl_s(conn, "177.86.19.1", cfg, base_ttl_s=1000) == 1000


def test_next_ttl_s_grows_with_offenses(conn):
    cfg = _cfg(base_ttl_s=None, factor=4, max_steps=5, max_ttl_s=10**9)
    src = "177.86.19.2"
    assert escalation.next_ttl_s(conn, src, cfg, base_ttl_s=100) == 100
    _add_offense(conn, src)
    assert escalation.next_ttl_s(conn, src, cfg, base_ttl_s=100) == 400
    _add_offense(conn, src)
    assert escalation.next_ttl_s(conn, src, cfg, base_ttl_s=100) == 1600


def test_next_ttl_s_caps_at_max_ttl_s(conn):
    cfg = _cfg(base_ttl_s=None, factor=4, max_steps=5, max_ttl_s=500)
    src = "177.86.19.3"
    for _ in range(5):
        _add_offense(conn, src)
    assert escalation.next_ttl_s(conn, src, cfg, base_ttl_s=100) == 500


def test_next_ttl_s_caps_step_growth_at_max_steps(conn):
    cfg = _cfg(base_ttl_s=None, factor=2, max_steps=2, max_ttl_s=10**9)
    src = "177.86.19.4"
    for _ in range(10):  # bem mais reincidências que max_steps
        _add_offense(conn, src)
    # trava no step 2 (100 * 2^2 = 400), não continua crescendo pra sempre
    assert escalation.next_ttl_s(conn, src, cfg, base_ttl_s=100) == 400


def test_next_ttl_s_ignores_offenses_outside_tracking_window(conn):
    cfg = _cfg(base_ttl_s=None, factor=4, tracking_window_s=3600)
    src = "177.86.19.5"
    _add_offense(conn, src, ts_ago=7200)  # fora da janela de 1h
    assert escalation.next_ttl_s(conn, src, cfg, base_ttl_s=100) == 100


def test_next_ttl_s_disabled_returns_base_unchanged(conn):
    cfg = _cfg(enabled=False, base_ttl_s=None, factor=4)
    src = "177.86.19.6"
    for _ in range(3):
        _add_offense(conn, src)
    assert escalation.next_ttl_s(conn, src, cfg, base_ttl_s=100) == 100


def test_next_ttl_s_cfg_base_ttl_s_overrides_param(conn):
    cfg = _cfg(base_ttl_s=999)
    assert escalation.next_ttl_s(conn, "177.86.19.7", cfg, base_ttl_s=100) == 999


def test_next_ttl_s_counts_ssh_and_flowspec_mechanisms(conn):
    cfg = _cfg(base_ttl_s=None, factor=4, max_steps=5, max_ttl_s=10**9)
    src = "177.86.19.8"
    _add_offense(conn, src, mechanism="ssh")
    _add_offense(conn, src, mechanism="flowspec")
    assert escalation.next_ttl_s(conn, src, cfg, base_ttl_s=100) == 100 * (4 ** 2)


def test_next_ttl_s_raises_without_any_base(conn):
    cfg = _cfg(base_ttl_s=None)
    with pytest.raises(ValueError):
        escalation.next_ttl_s(conn, "177.86.19.9", cfg)


# --- load_config/save_config ------------------------------------------------

def test_load_config_missing_file_returns_defaults(tmp_path):
    cfg = escalation.load_config(str(tmp_path / "nao-existe.yaml"))
    assert cfg == escalation.DEFAULT_CONFIG


def test_save_config_roundtrip(tmp_path):
    path = str(tmp_path / "escalation.yaml")
    updated = escalation.save_config({"factor": 3, "base_ttl_s": 1800}, path)
    assert updated["factor"] == 3
    assert updated["base_ttl_s"] == 1800
    assert escalation.load_config(path)["factor"] == 3


def test_save_config_rejects_unknown_key(tmp_path):
    path = str(tmp_path / "escalation.yaml")
    with pytest.raises(ValueError):
        escalation.save_config({"nao_existe": 1}, path)


def test_save_config_rejects_factor_not_greater_than_one(tmp_path):
    path = str(tmp_path / "escalation.yaml")
    with pytest.raises(ValueError):
        escalation.save_config({"factor": 1}, path)


def test_save_config_rejects_negative_numbers(tmp_path):
    path = str(tmp_path / "escalation.yaml")
    with pytest.raises(ValueError):
        escalation.save_config({"max_ttl_s": -1}, path)
