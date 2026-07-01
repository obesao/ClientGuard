"""Servidor de controle via Unix socket — mesmo protocolo (uma linha JSON de request,
uma linha JSON de resposta, conexão fechada) do socket do FlowGuard, consumido pelo
clientguard-cli. Implementado com threads (não asyncio) pra combinar com o resto do
daemon do ClientGuard, que já roda a captura em thread separada."""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import socketserver
import threading
import time
from pathlib import Path

import configio
import storage

LOG = logging.getLogger("clientguard.socket")

WHITELIST_HEADER = (
    "# whitelist.yaml — src_ip/prefixos que NUNCA devem gerar alerta no ClientGuard\n"
    "# (servidores de e-mail/DNS/NTP legítimos de clientes corporativos, backups, etc.)\n"
    "# Editável diretamente ou via: clientguard-cli whitelist add|del <ip>"
)
CUSTOMERS_HEADER = (
    "# customers.yaml — cadastro de redes de clientes (network CIDR -> customer_prefix/nome).\n"
    "# src_ip do flow é resolvido pro customer_prefix se cair dentro de alguma 'network' aqui\n"
    "# (aceita /32 pra host único ou qualquer CIDR). Se já existir cadastro em outro sistema\n"
    "# (RADIUS, ERP), preferir reusar aquele; este arquivo é o fallback.\n"
    "# Editável diretamente ou via: clientguard-cli customers add|del <network> <prefix>"
)


class _RequestHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        try:
            line = self.rfile.readline()
            if not line:
                return
            try:
                request = json.loads(line.decode("utf-8"))
            except json.JSONDecodeError:
                response = {"ok": False, "error": "JSON inválido"}
            else:
                response = self.server.dispatch(request)
            self.wfile.write((json.dumps(response) + "\n").encode("utf-8"))
        except (ConnectionResetError, BrokenPipeError):
            pass  # cliente (ex.: clientguard-cli) desconectou antes de receber a resposta
        except Exception:
            LOG.exception("erro ao atender cliente do socket")


class SocketServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, daemon):
        self.daemon_ref = daemon
        self.sock_path = daemon.config["daemon"]["socket"]
        Path(self.sock_path).parent.mkdir(parents=True, exist_ok=True)
        try:
            os.unlink(self.sock_path)
        except FileNotFoundError:
            pass
        super().__init__(self.sock_path, _RequestHandler)
        os.chmod(self.sock_path, 0o600)

    def close(self) -> None:
        self.shutdown()
        self.server_close()
        try:
            os.unlink(self.sock_path)
        except FileNotFoundError:
            pass

    def dispatch(self, request: dict) -> dict:
        cmd = request.get("cmd", "")
        handler = getattr(self, f"_cmd_{cmd}", None)
        if handler is None:
            return {"ok": False, "error": f"comando desconhecido: {cmd}"}
        try:
            return handler(request)
        except Exception as exc:
            LOG.exception("erro ao executar comando %s", cmd)
            return {"ok": False, "error": str(exc)}

    # --- comandos -----------------------------------------------------

    def _cmd_status(self, request: dict) -> dict:
        d = self.daemon_ref
        interval = d.config["database"]["aggregate_interval_s"]
        with d.db_lock:
            stats = storage.daemon_stats(d.conn, interval)
        return {
            "ok": True, "pid": os.getpid(), "uptime_s": time.time() - d.started_at,
            "iface": d.config["capture"]["iface"], "bpf_filter": d.config["capture"]["bpf_filter"],
            "n_customers": len(d.customers), "n_whitelist": len(d.whitelist),
            **stats,
        }

    def _cmd_top(self, request: dict) -> dict:
        d = self.daemon_ref
        limit = int(request.get("limit", 20))
        window_s = int(request.get("window_s") or d.config["database"]["aggregate_interval_s"])
        with d.db_lock:
            top = storage.top_src_ips(d.conn, window_s, limit)
        return {"ok": True, "top": top}

    def _cmd_suspicious(self, request: dict) -> dict:
        d = self.daemon_ref
        resolved = bool(request.get("history", False))
        since_s = int(request.get("since_s", 86400))
        with d.db_lock:
            items = storage.list_suspicious_clients(d.conn, resolved=resolved, since_s=since_s)
        return {"ok": True, "suspicious": items}

    def _cmd_resolve(self, request: dict) -> dict:
        signal_id = request.get("id")
        if signal_id is None:
            return {"ok": False, "error": "id obrigatório"}
        d = self.daemon_ref
        with d.db_lock:
            found = storage.resolve_signal(d.conn, int(signal_id))
        if not found:
            return {"ok": False, "error": "sinal não encontrado ou já resolvido"}
        return {"ok": True}

    def _cmd_whitelist_add(self, request: dict) -> dict:
        ip = request.get("ip")
        if not ip:
            return {"ok": False, "error": "ip obrigatório"}
        d = self.daemon_ref
        path = d.config["whitelist_file"]
        items = configio.load_yaml_list(path)
        if ip in items:
            return {"ok": False, "error": "ip já está na whitelist"}
        items.append(ip)
        configio.save_yaml_list(path, items, header_comment=WHITELIST_HEADER)
        d.reload_config()
        return {"ok": True}

    def _cmd_whitelist_del(self, request: dict) -> dict:
        ip = request.get("ip")
        if not ip:
            return {"ok": False, "error": "ip obrigatório"}
        d = self.daemon_ref
        path = d.config["whitelist_file"]
        items = configio.load_yaml_list(path)
        if ip not in items:
            return {"ok": False, "error": "ip não está na whitelist"}
        items.remove(ip)
        configio.save_yaml_list(path, items, header_comment=WHITELIST_HEADER)
        d.reload_config()
        return {"ok": True}

    def _cmd_customers_add(self, request: dict) -> dict:
        network = request.get("network")
        prefix = request.get("prefix")
        if not network or not prefix:
            return {"ok": False, "error": "network e prefix obrigatórios"}
        try:
            ipaddress.ip_network(network, strict=False)
        except ValueError:
            return {"ok": False, "error": f"network inválida: {network}"}
        d = self.daemon_ref
        path = d.config["customer_registry"]
        items = configio.load_yaml_list(path)
        if any(entry.get("network") == network for entry in items):
            return {"ok": False, "error": "network já cadastrada"}
        entry = {"network": network, "prefix": prefix}
        if request.get("name"):
            entry["name"] = request["name"]
        items.append(entry)
        configio.save_yaml_list(path, items, header_comment=CUSTOMERS_HEADER)
        d.reload_config()
        return {"ok": True}

    def _cmd_customers_del(self, request: dict) -> dict:
        network = request.get("network")
        if not network:
            return {"ok": False, "error": "network obrigatória"}
        d = self.daemon_ref
        path = d.config["customer_registry"]
        items = configio.load_yaml_list(path)
        filtered = [entry for entry in items if entry.get("network") != network]
        if len(filtered) == len(items):
            return {"ok": False, "error": "network não cadastrada"}
        configio.save_yaml_list(path, filtered, header_comment=CUSTOMERS_HEADER)
        d.reload_config()
        return {"ok": True}

    def _cmd_reload(self, request: dict) -> dict:
        self.daemon_ref.reload_config()
        return {"ok": True}

    def _cmd_stop(self, request: dict) -> dict:
        threading.Timer(0.2, self.daemon_ref.stop).start()
        return {"ok": True, "message": "encerrando..."}
