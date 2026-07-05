"""Leitura/gravação de whitelist.yaml e customers.yaml — arquivos separados do
config.yaml pra que edições via CLI (whitelist add/del, customers add/del) não
precisem reescrever o config inteiro nem tocar em comentários do operador."""

from __future__ import annotations

from pathlib import Path

import yaml

_MODULE_DIR = Path(__file__).resolve().parent
DEFAULT_DETECTION_TEMPLATES_PATH = str(_MODULE_DIR / "detection_templates.yaml")
DEFAULT_DETECTION_OVERRIDES_PATH = str(_MODULE_DIR / "detection_overrides.yaml")


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
    """Atalho de 1 chave só — ver save_feature_toggles (usada pelo botão "Aplicar
    novas configurações" do portal, que manda todas as mudanças pendentes de uma vez)."""
    return save_feature_toggles(path, {key: value})


def save_feature_toggles(path: str, changes: dict) -> dict:
    """Lê o estado atual (mesclado com defaults), aplica TODAS as mudanças de uma vez
    numa única leitura+escrita, e persiste só chaves conhecidas — evita que um
    toggles.yaml corrompido/editado à mão propague lixo. Retorna o dict completo
    já atualizado.

    Fazer isso numa função só (1 read + 1 write) em vez de 1 save_feature_toggle()
    por chave é o que torna a operação atômica: o socket do ClientGuard atende
    conexões em threads de verdade (ThreadingUnixStreamServer, não asyncio), então
    N chamadas independentes rodando em paralelo (ex.: aplicar várias funções de
    uma vez no portal) poderiam intercalar leitura/escrita e perder uma mudança
    (thread A lê {x:1,y:1}, thread B lê {x:1,y:1}, A grava {x:0,y:1}, B grava
    {x:1,y:0} — a mudança de A em x se perde). Com tudo numa chamada só, o portal
    manda 1 requisição com o dict inteiro de mudanças em vez de 1 por checkbox."""
    unknown = sorted(k for k in changes if k not in DEFAULT_FEATURE_TOGGLES)
    if unknown:
        raise ValueError(f"toggle(s) desconhecido(s): {', '.join(unknown)}")
    current = load_feature_toggles(path)
    for key, value in changes.items():
        current[key] = bool(value)
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(TOGGLES_HEADER.rstrip() + "\n")
        yaml.safe_dump(current, fh, sort_keys=False, allow_unicode=True)
    return current


# --- detection_templates.yaml: perfis de limiar reutilizáveis por tipo de rede -----
# Associado a um customer_prefix via `template:` em customers.yaml (ver detector.py::
# run_all, que resolve o limiar efetivo por prefixo: template > detection.* global).
# Arquivo ausente/vazio = nenhum template disponível, todo prefixo cai no valor
# global de config.yaml — mesmo comportamento de antes desta feature existir.
DETECTION_TEMPLATES_HEADER = (
    "# detection_templates.yaml — perfis de limiar de detecção reutilizáveis por tipo de\n"
    "# rede/barramento, associados a um customer_prefix via `template:` em customers.yaml.\n"
    "# Evita recalibrar os mesmos números pra cada /24 novo do mesmo perfil. Editável via\n"
    "# portal (aba ClientGuard > Configurações) ou clientguard-cli detection templates set|del.\n"
    "#\n"
    "# Ordem de precedência (do mais específico pro mais genérico): template > detection.*\n"
    "# em config.yaml (usado por qualquer prefixo sem `template` atribuído). client_multiplier\n"
    "# (customers.yaml) continua aplicando por cima do limiar já resolvido, quando os dois se\n"
    "# acumulam (ex.: pool CGNAT pós-NAT com template E multiplier)."
)
# chaves aceitas dentro de cada template — mesmas que detector.py::_template_overrides
# sabe resolver por prefixo hoje (scan_max_avg_bytes continua só global de propósito,
# não faz parte do fan-out que varia por perfil de rede).
DETECTION_TEMPLATE_KEYS = {"scan_horizontal_hosts", "scan_vertical_ports"}


def load_detection_templates(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except FileNotFoundError:
        return {}
    return data or {}


def save_detection_template(path: str, name: str, values: dict, description: str = "") -> dict:
    """Cria ou substitui (nome já existente = sobrescreve) um template inteiro — não é
    merge parcial de campos, pra não deixar uma chave antiga órfã se o operador trocar
    de ideia sobre o que o template define. `name` vira a chave no YAML; validação de
    slug simples (sem espaço/maiúscula) evita template com nome que colide visualmente
    com outro ou quebra a leitura em customers.yaml::template."""
    if not name or not name.replace("_", "").replace("-", "").isalnum() or name != name.lower():
        raise ValueError("nome do template deve ser minúsculo, só letras/números/_/-")
    unknown = sorted(k for k in values if k not in DETECTION_TEMPLATE_KEYS)
    if unknown:
        raise ValueError(f"campo(s) desconhecido(s) no template: {', '.join(unknown)}")
    for key, val in values.items():
        if not isinstance(val, int) or isinstance(val, bool) or val <= 0:
            raise ValueError(f"{key} deve ser um inteiro positivo")
    current = load_detection_templates(path)
    entry = dict(values)
    if description:
        entry["description"] = description
    elif name in current and current[name].get("description"):
        entry["description"] = current[name]["description"]  # preserva descrição existente
    current[name] = entry
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(DETECTION_TEMPLATES_HEADER.rstrip() + "\n")
        yaml.safe_dump(current, fh, sort_keys=False, allow_unicode=True)
    return current


def delete_detection_template(path: str, name: str) -> dict:
    current = load_detection_templates(path)
    if name not in current:
        raise ValueError(f"template '{name}' não existe")
    del current[name]
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(DETECTION_TEMPLATES_HEADER.rstrip() + "\n")
        yaml.safe_dump(current, fh, sort_keys=False, allow_unicode=True)
    return current


# --- detection_overrides.yaml: ajuste fino dos limiares de config.yaml::detection ---
# via portal/CLI, sem tocar no config.yaml principal (mesmo motivo de toggles/
# customers/whitelist: editar via portal não pode reescrever, e perder os comentários
# de, o config.yaml). Aplicado por cima de config.yaml::detection na carga E no
# reload (ClientGuardDaemon.reload_config) — muda o limiar sem reiniciar o daemon,
# diferente de mudar config.yaml direto (só lido na inicialização).
DETECTION_OVERRIDES_HEADER = (
    "# detection_overrides.yaml — ajuste fino dos limiares de detection.* em\n"
    "# config.yaml, aplicado por cima na carga e no reload (sem reiniciar o daemon).\n"
    "# Editável via portal (aba ClientGuard > Configurações) ou\n"
    "# clientguard-cli detection set. Vazio = usa os valores de config.yaml sem ajuste."
)
DETECTION_TUNABLE_KEYS = {
    "scan_horizontal_hosts", "scan_vertical_ports", "scan_max_avg_bytes",
    "amplifier_ports", "amplifier_min_bps", "spam_ports", "spam_min_distinct_dest",
    "coordinated_min_clients", "common_service_ports", "dns_tunneling_min_queries",
}


def load_detection_overrides(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except FileNotFoundError:
        return {}
    data = data or {}
    return {k: v for k, v in data.items() if k in DETECTION_TUNABLE_KEYS}


def save_detection_overrides(path: str, changes: dict) -> dict:
    """Read-modify-write atômico (mesmo padrão de save_feature_toggles) — aplica todas
    as mudanças pendentes numa leitura+escrita só. Passar valor None pra uma chave
    REMOVE o override (volta a usar o valor de config.yaml), não grava null."""
    unknown = sorted(k for k in changes if k not in DETECTION_TUNABLE_KEYS)
    if unknown:
        raise ValueError(f"limiar(es) desconhecido(s): {', '.join(unknown)}")
    current = load_detection_overrides(path)
    for key, value in changes.items():
        if value is None:
            current.pop(key, None)
        else:
            current[key] = value
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(DETECTION_OVERRIDES_HEADER.rstrip() + "\n")
        yaml.safe_dump(current, fh, sort_keys=False, allow_unicode=True)
    return current
