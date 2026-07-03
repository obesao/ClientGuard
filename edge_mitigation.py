"""edge_mitigation — aplica/reverte um bloqueio de IP direto no roteador de borda via
SSH (Netmiko), dirigido por sinal detectado pelo ClientGuard.

Reaproveita a lista de equipamentos/credenciais já cadastrada no Modo Guerra do
FlowGuard (flowguard/warmode/executor.py: warmode.yaml) — evita duplicar a senha SSH
do mesmo equipamento em dois lugares. A técnica em si (entrar num ACL numerado e
inserir/remover uma regra de negação por IP de origem) é decidida aqui, não lá: o Modo
Guerra manda comandos de modo EXEC genéricos (send_command) pensados pra uma lista fixa
de comandos por equipamento, enquanto isto precisa entrar em modo de configuração
(send_config_set) com um IP substituído dinamicamente a cada chamada.

acl_number/apply_commands/revert_commands em edge_mitigation.yaml são só um template —
a sintaxe exata (e o número do ACL já aplicado na interface de clientes) depende de como
a borda real está configurada; ajustar esse arquivo antes de habilitar em produção.

Netmiko é importado só dentro das funções que precisam de fato conectar, não no topo do
módulo, pra não quebrar a coleta de testes em ambientes onde a lib não está instalada."""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import time
from contextlib import nullcontext
from pathlib import Path

import yaml

import storage

LOG = logging.getLogger("clientguard.edge_mitigation")

DEFAULT_CONFIG_PATH = str(Path(__file__).resolve().parent / "edge_mitigation.yaml")
# clientguard.service roda com ProtectSystem=strict e ReadWritePaths restrito a
# /root/clientguard e /run — /var/log NÃO é gravável (achado real: a primeira versão
# apontava pra /var/log/clientguard-edge-audit.jsonl e falhava silenciosamente com
# "Read-only file system" a cada chamada). Diferente do FlowGuard (warmode/executor.py),
# cujo serviço não tem esse hardening.
AUDIT_LOG_PATH = str(Path(__file__).resolve().parent / "logs" / "edge-audit.jsonl")

DEFAULT_CONFIG = {
    "warmode_device": "",
    "acl_number": 3999,
    "default_ttl_s": 21600,
    "apply_commands": ["acl number {acl_number}", "rule deny ip source {ip} 0"],
    "revert_commands": ["acl number {acl_number}", "undo rule deny ip source {ip} 0"],
    "auto_mitigate": {
        "port_scan_horizontal": False,
        "port_scan_vertical": False,
        "amplifier_hosted": False,
        "spam_bot": False,
        "malicious_contact": False,
        "coordinated_destination": False,
        "dns_tunneling": False,
    },
}


def load_config(path: str = DEFAULT_CONFIG_PATH) -> dict:
    p = Path(path)
    if not p.exists():
        return json.loads(json.dumps(DEFAULT_CONFIG))  # cópia funda, sem depender de copy.deepcopy
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    merged = json.loads(json.dumps(DEFAULT_CONFIG))
    merged.update({k: v for k, v in data.items() if k != "auto_mitigate"})
    merged["auto_mitigate"].update(data.get("auto_mitigate") or {})
    return merged


def save_auto_mitigate(changes: dict, default_ttl_s: int | None = None,
                        path: str = DEFAULT_CONFIG_PATH) -> dict:
    """Read-modify-write atômico só dos campos editáveis via portal/CLI (auto_mitigate
    por detector + default_ttl_s). acl_number/apply_commands/revert_commands ficam
    editáveis só direto no arquivo YAML — expor esses campos por um formulário web
    abriria um canal pra injetar comando VRP arbitrário no roteador."""
    unknown = sorted(k for k in changes if k not in DEFAULT_CONFIG["auto_mitigate"])
    if unknown:
        raise ValueError(f"detector(es) desconhecido(s): {', '.join(unknown)}")
    current = load_config(path)
    current["auto_mitigate"].update({k: bool(v) for k, v in changes.items()})
    if default_ttl_s is not None:
        current["default_ttl_s"] = int(default_ttl_s)
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(
            "# edge_mitigation.yaml — mitigação direta na borda (SSH/ACL) por IP de\n"
            "# cliente abusivo. auto_mitigate/default_ttl_s são editáveis pelo portal ou\n"
            "# clientguard-cli edge auto set; acl_number/apply_commands/revert_commands só\n"
            "# à mão aqui (ajuste pro ACL/sintaxe reais já aplicados na borda).\n",
        )
        yaml.safe_dump(current, fh, sort_keys=False, allow_unicode=True)
    return current


def _load_warmode_device(cfg: dict, flowguard_path: str) -> dict:
    device_name = cfg.get("warmode_device")
    if not device_name:
        raise RuntimeError("warmode_device não configurado em edge_mitigation.yaml")
    warmode_yaml = os.path.join(flowguard_path, "warmode.yaml")
    if not Path(warmode_yaml).exists():
        raise RuntimeError(f"{warmode_yaml} não encontrado (Modo Guerra do FlowGuard não configurado)")
    data = yaml.safe_load(Path(warmode_yaml).read_text(encoding="utf-8")) or {}
    for device in data.get("devices") or []:
        if device.get("name") == device_name:
            return device
    raise RuntimeError(f"equipamento '{device_name}' não encontrado em {warmode_yaml}")


def _run_commands(ip: str, cfg: dict, flowguard_path: str, templates: list[str], timeout: float) -> dict:
    from netmiko import ConnectHandler
    from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

    # resolvido ANTES de qualquer coisa que possa falhar — o botão Detalhes do
    # portal mostra isso mesmo quando a aplicação falhou (ex: equipamento não
    # encontrado), pra sempre dar pra ver o que SERIA mandado.
    commands = [tpl.format(ip=ip, acl_number=cfg["acl_number"]) for tpl in templates]
    t0 = time.monotonic()
    try:
        device = _load_warmode_device(cfg, flowguard_path)
    except RuntimeError as exc:
        return {"ok": False, "error": str(exc), "output": "", "elapsed_s": 0.0, "commands": commands}

    conn = None
    try:
        conn = ConnectHandler(
            device_type=device["device_type"], host=device["host"], port=device.get("port", 22),
            username=device["username"], password=device["password"],
            secret=device.get("enable_secret", device.get("password", "")),
            timeout=timeout, conn_timeout=timeout, fast_cli=False,
        )
        if device.get("enable_mode"):
            conn.enable()
        output = conn.send_config_set(commands, read_timeout=timeout)
        return {"ok": True, "output": output, "elapsed_s": round(time.monotonic() - t0, 1), "commands": commands}
    except NetmikoAuthenticationException:
        return {"ok": False, "error": "autenticação SSH falhou (usuário/senha)", "output": "",
                "elapsed_s": round(time.monotonic() - t0, 1), "commands": commands}
    except NetmikoTimeoutException:
        return {"ok": False, "error": "timeout de conexão SSH", "output": "",
                "elapsed_s": round(time.monotonic() - t0, 1), "commands": commands}
    except Exception as exc:
        return {"ok": False, "error": str(exc), "output": "", "elapsed_s": round(time.monotonic() - t0, 1), "commands": commands}
    finally:
        if conn is not None:
            try:
                conn.disconnect()
            except Exception:
                pass


def _audit(action: str, ip: str, result: dict) -> None:
    record = {
        "ts": int(time.time()), "action": action, "ip": ip, "ok": result["ok"],
        "elapsed_s": result.get("elapsed_s"), "error": result.get("error"),
    }
    try:
        Path(AUDIT_LOG_PATH).parent.mkdir(parents=True, exist_ok=True)
        with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
    except OSError:
        LOG.exception("falha ao gravar audit log da mitigação de borda")


def apply_block(ip: str, cfg: dict, flowguard_path: str, timeout: float = 20.0) -> dict:
    result = _run_commands(ip, cfg, flowguard_path, cfg["apply_commands"], timeout)
    _audit("apply", ip, result)
    return result


def revert_block(ip: str, cfg: dict, flowguard_path: str, timeout: float = 20.0) -> dict:
    result = _run_commands(ip, cfg, flowguard_path, cfg["revert_commands"], timeout)
    _audit("revert", ip, result)
    return result


# --- orquestração (executor + storage numa chamada só) ---------------------

def apply_and_record(conn: sqlite3.Connection, db_lock, src_ip: str, signal_id: int | None,
                      ttl_s: int | None, trigger_type: str, cfg: dict, flowguard_path: str) -> dict:
    """Idempotente: se já existe mitigação ativa pro mesmo src_ip, só estende o TTL em
    vez de mandar o comando de novo (evita empilhar regras duplicadas no ACL)."""
    lock = db_lock or nullcontext()
    with lock:
        existing = storage.get_active_edge_mitigation(conn, src_ip)
    if existing:
        with lock:
            storage.extend_edge_mitigation(conn, existing["id"], ttl_s)
        return {"ok": True, "id": existing["id"], "already_active": True}

    result = apply_block(src_ip, cfg, flowguard_path)
    with lock:
        mitigation_id = storage.insert_edge_mitigation(
            conn, src_ip, signal_id, ttl_s, trigger_type,
            apply_commands=result.get("commands"), apply_output=result.get("output"),
            status="active" if result["ok"] else "failed",
            error=None if result["ok"] else result.get("error"),
        )
    if not result["ok"]:
        return {"ok": False, "error": result.get("error", "falha desconhecida ao aplicar mitigação"), "id": mitigation_id}
    return {"ok": True, "id": mitigation_id}


def revert_and_record(conn: sqlite3.Connection, db_lock, mitigation_id: int,
                       cfg: dict, flowguard_path: str) -> dict:
    lock = db_lock or nullcontext()
    with lock:
        row = storage.get_edge_mitigation(conn, mitigation_id)
    if not row:
        return {"ok": False, "error": "mitigação não encontrada"}
    result = revert_block(row["src_ip"], cfg, flowguard_path)
    with lock:
        storage.mark_edge_reverted(
            conn, mitigation_id, error=None if result["ok"] else result.get("error"),
            revert_commands=result.get("commands"), revert_output=result.get("output"),
        )
    return result


def expire_due(conn: sqlite3.Connection, db_lock, cfg: dict, flowguard_path: str) -> int:
    """Chamado periodicamente pelo loop do daemon — reverte mitigações cujo TTL venceu.
    mechanism='ssh' explícito: só processa mitigações deste módulo legado — as novas
    (mechanism='flowspec') são responsabilidade de flowspec_mitigation.expire_due, que
    roda em paralelo (ver clientguard.py)."""
    lock = db_lock or nullcontext()
    with lock:
        due = storage.list_due_edge_mitigations(conn, mechanism="ssh")
    for row in due:
        revert_and_record(conn, db_lock, row["id"], cfg, flowguard_path)
    return len(due)


def trigger_async(conn: sqlite3.Connection, db_lock, src_ip: str, signal_id: int,
                   cfg: dict, flowguard_path: str) -> None:
    """Dispara apply_and_record em thread separada — usado pelo gatilho automático dos
    detectores, que não pode travar o ciclo de agregação esperando uma conexão SSH."""
    def _run() -> None:
        try:
            apply_and_record(conn, db_lock, src_ip, signal_id, cfg.get("default_ttl_s"),
                              "auto", cfg, flowguard_path)
        except Exception:
            LOG.exception("falha ao aplicar mitigação automática na borda para %s", src_ip)

    threading.Thread(target=_run, daemon=True, name="clientguard-edge-auto").start()
