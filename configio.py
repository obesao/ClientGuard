"""Leitura/gravação de whitelist.yaml e customers.yaml — arquivos separados do
config.yaml pra que edições via CLI (whitelist add/del, customers add/del) não
precisem reescrever o config inteiro nem tocar em comentários do operador."""

from __future__ import annotations

from pathlib import Path

import yaml


def load_yaml_list(path: str) -> list:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except FileNotFoundError:
        return []
    return data or []


def save_yaml_list(path: str, items: list, header_comment: str = "") -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        if header_comment:
            fh.write(header_comment.rstrip() + "\n")
        yaml.safe_dump(items, fh, sort_keys=False, allow_unicode=True)
