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


# --- toggles.yaml: liga/desliga por checkbox (portal) de cada detector e da IA -----
# Arquivo separado do config.yaml pelo mesmo motivo de whitelist/customers: editar via
# portal não deve reescrever (e perder os comentários de) o config.yaml principal.
# Ausência do arquivo (ou de uma chave dele) = habilitado, igual ao comportamento antes
# dessa feature existir — nenhum sinal se torna silenciosamente inativo por upgrade.
DEFAULT_FEATURE_TOGGLES = {
    "scan_horizontal": True,
    "scan_vertical": True,
    "amplifier": True,
    "spam": True,
    "malicious_contact": True,
    "coordinated_destination": True,
    "dns_tunneling": True,
    "ai_explanations": True,
}

TOGGLES_HEADER = (
    "# toggles.yaml — habilita/desabilita cada detector e a explicação por IA, editável\n"
    "# via portal (aba ClientGuard > Configurações) ou clientguard-cli toggles set.\n"
    "# Chave ausente = habilitado (mesmo padrão de antes desta feature existir)."
)


def load_feature_toggles(path: str) -> dict:
    """Retorna os toggles mesclados com os defaults — nunca falta uma chave, mesmo se
    o arquivo não existir ainda ou tiver sido criado com só algumas chaves."""
    merged = dict(DEFAULT_FEATURE_TOGGLES)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except FileNotFoundError:
        data = None
    if data:
        merged.update({k: bool(v) for k, v in data.items() if k in DEFAULT_FEATURE_TOGGLES})
    return merged


def save_feature_toggle(path: str, key: str, value: bool) -> dict:
    """Lê o estado atual (mesclado com defaults), aplica uma mudança e persiste só as
    chaves conhecidas — evita que um toggles.yaml corrompido/editado à mão propague
    lixo. Retorna o dict completo já atualizado."""
    if key not in DEFAULT_FEATURE_TOGGLES:
        raise ValueError(f"toggle desconhecido: {key}")
    current = load_feature_toggles(path)
    current[key] = bool(value)
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(TOGGLES_HEADER.rstrip() + "\n")
        yaml.safe_dump(current, fh, sort_keys=False, allow_unicode=True)
    return current
