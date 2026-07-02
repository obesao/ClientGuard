"""Testa leitura/gravação de whitelist.yaml/customers.yaml."""

from __future__ import annotations

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
