"""Testa leitura/gravação de whitelist.yaml/customers.yaml."""

from __future__ import annotations

import pytest

import configio


def test_load_yaml_list_missing_file_returns_empty(tmp_path):
    assert configio.load_yaml_list(str(tmp_path / "nao-existe.yaml")) == []


def test_save_and_load_roundtrip(tmp_path):
    path = tmp_path / "whitelist.yaml"
    configio.save_yaml_list(str(path), ["1.2.3.4", "5.6.7.8"])
    assert configio.load_yaml_list(str(path)) == ["1.2.3.4", "5.6.7.8"]


def test_save_yaml_list_writes_header_comment(tmp_path):
    path = tmp_path / "whitelist.yaml"
    configio.save_yaml_list(str(path), ["1.2.3.4"], header_comment="# cabeçalho de teste")
    content = path.read_text(encoding="utf-8")
    assert content.startswith("# cabeçalho de teste")
    assert "1.2.3.4" in content


def test_save_yaml_list_creates_parent_dirs(tmp_path):
    path = tmp_path / "nested" / "dir" / "customers.yaml"
    configio.save_yaml_list(str(path), [{"network": "1.2.3.0/24", "prefix": "1.2.3.0/24"}])
    loaded = configio.load_yaml_list(str(path))
    assert loaded == [{"network": "1.2.3.0/24", "prefix": "1.2.3.0/24"}]


def test_load_feature_toggles_missing_file_returns_all_enabled(tmp_path):
    toggles = configio.load_feature_toggles(str(tmp_path / "nao-existe.yaml"))
    assert toggles == configio.DEFAULT_FEATURE_TOGGLES


def test_load_feature_toggles_merges_partial_file(tmp_path):
    path = tmp_path / "toggles.yaml"
    path.write_text("spam: false\n", encoding="utf-8")
    toggles = configio.load_feature_toggles(str(path))
    assert toggles["spam"] is False
    assert toggles["scan_horizontal"] is True  # ausente no arquivo -> default habilitado


def test_load_feature_toggles_ignores_unknown_keys(tmp_path):
    path = tmp_path / "toggles.yaml"
    path.write_text("chave_inventada: true\n", encoding="utf-8")
    toggles = configio.load_feature_toggles(str(path))
    assert "chave_inventada" not in toggles


def test_save_feature_toggle_roundtrip(tmp_path):
    path = tmp_path / "toggles.yaml"
    updated = configio.save_feature_toggle(str(path), "amplifier", False)
    assert updated["amplifier"] is False
    assert configio.load_feature_toggles(str(path))["amplifier"] is False
    # outras chaves continuam com o default, persistidas no arquivo
    assert configio.load_feature_toggles(str(path))["dns_tunneling"] is True


def test_save_feature_toggle_unknown_key_raises(tmp_path):
    path = tmp_path / "toggles.yaml"
    with pytest.raises(ValueError):
        configio.save_feature_toggle(str(path), "nao_existe", True)
