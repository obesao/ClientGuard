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
import control
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


def _bucket_for_window(window_s: int) -> int:
    """Tamanho do bucket da série temporal — escala com a janela pra manter a
    contagem de pontos do gráfico razoável (dezenas a ~170, não milhares)."""
    if window_s <= 3600:
        return 60
    if window_s <= 21600:
        return 300
    if window_s <= 86400:
        return 900
    return 3600


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

    def _cmd_client_detail(self, request: dict) -> dict:
        src_ip = request.get("src_ip")
        if not src_ip:
            return {"ok": False, "error": "src_ip obrigatório"}
        d = self.daemon_ref
        window_s = int(request.get("window_s") or d.config["database"]["aggregate_interval_s"])
        bucket_s = _bucket_for_window(window_s)
        with d.db_lock:
            timeseries = storage.client_usage_timeseries(d.conn, src_ip, window_s, bucket_s)
            top_destinations = storage.client_top_destinations(d.conn, src_ip, window_s, limit=10)
        return {"ok": True, "timeseries": timeseries, "top_destinations": top_destinations}

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

    def _cmd_clear_suspicious(self, request: dict) -> dict:
        d = self.daemon_ref
        with d.db_lock:
            cleared = storage.clear_open_signals(d.conn)
        return {"ok": True, "cleared": cleared}

    # --- toggles: habilita/desabilita cada detector e a IA via portal/CLI ---

    def _cmd_toggles(self, request: dict) -> dict:
        return {"ok": True, "toggles": self.daemon_ref.toggles}

    def _cmd_set_toggle(self, request: dict) -> dict:
        key = request.get("key")
        if key not in configio.DEFAULT_FEATURE_TOGGLES:
            return {"ok": False, "error": f"toggle desconhecido: {key}"}
        d = self.daemon_ref
        path = d.config.get("feature_toggles_file", "")
        if not path:
            return {"ok": False, "error": "feature_toggles_file não configurado"}
        updated = configio.save_feature_toggle(path, key, bool(request.get("value")))
        d.reload_config()
        return {"ok": True, "toggles": updated}

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

    # --- bloqueio manual de IP (proxy pro FlowSpec do FlowGuard) ------------
    # ClientGuard não fala BGP nem tem seu próprio ExaBGP — só existe UMA sessão
    # com o roteador. Bloquear um cliente abusivo é a mesma coisa que o FlowGuard
    # já faz pra atacantes: uma regra FlowSpec discard por src_prefix. Por isso
    # isso é um proxy fino pro socket do FlowGuard, sem tabela/TTL própria aqui —
    # a regra "de verdade" (com expiração etc.) vive só em flowspec_rules do
    # FlowGuard, sem duplicar/divergir estado.

    def _fg_socket(self) -> str:
        return self.daemon_ref.config.get("flowguard_socket", "/var/run/flowguard.sock")

    def _cmd_block_add(self, request: dict) -> dict:
        ip = request.get("ip")
        if not ip:
            return {"ok": False, "error": "ip obrigatório"}
        try:
            prefix = str(ipaddress.ip_network(ip, strict=False))
        except ValueError:
            return {"ok": False, "error": f"IP/CIDR inválido: {ip}"}
        rule = {"src_prefix": prefix, "action": "discard", "label": "bloqueio manual via ClientGuard"}
        payload = {"cmd": "flowspec_add", "rule": rule}
        ttl_s = request.get("ttl_s")
        if ttl_s:
            payload["ttl_s"] = int(ttl_s)
        return control.send_command(self._fg_socket(), payload)

    def _cmd_block_del(self, request: dict) -> dict:
        rule_id = request.get("id")
        if not rule_id:
            return {"ok": False, "error": "id obrigatório"}
        return control.send_command(self._fg_socket(), {"cmd": "flowspec_del", "rule_id": rule_id})

    def _cmd_block_list(self, request: dict) -> dict:
        resp = control.send_command(self._fg_socket(), {"cmd": "rules"})
        if not resp.get("ok"):
            return resp
        # só regras de bloqueio por origem (discard/rate-limit) — RTBH é o
        # mecanismo de proteção de vítima do FlowGuard, não bloqueio de cliente
        blocks = [r for r in resp.get("rules", []) if r.get("src_prefix") and r.get("action") != "rtbh"]
        return {"ok": True, "blocks": blocks}

    def _cmd_reload(self, request: dict) -> dict:
        self.daemon_ref.reload_config()
        return {"ok": True}

    def _cmd_stop(self, request: dict) -> dict:
        threading.Timer(0.2, self.daemon_ref.stop).start()
        return {"ok": True, "message": "encerrando..."}
