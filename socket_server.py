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
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path

import configio
import control
import edge_mitigation
import flowspec_mitigation
import storage

LOG = logging.getLogger("clientguard.socket")


@contextmanager
def _read_only_conn(db_path: str):
    """Conexão SQLite dedicada e somente-leitura, fora do db_lock do daemon — o
    SQLite em modo WAL permite leitores concorrentes sem bloquear nem ser bloqueado
    pelo escritor (ciclo de agregação/detecção no MainThread, que segura d.db_lock
    por vários segundos sob tabela grande). Achado real em produção: todo comando de
    leitura do socket (status, top, sinais suspeitos, mitigações de borda...)
    compartilhava a MESMA conexão + o MESMO lock global usado pela escrita — uma
    query de detecção lenta travava até consultas triviais por 10-20s, gerando
    "timeout ao falar com o daemon" constante no portal (confirmado com py-spy: não
    era deadlock, era fila atrás do mesmo lock). Escrita continua sempre via
    d.conn/d.db_lock, sem mudança — só leitura passou a usar isto."""
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5.0)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

# Protege o read-modify-write de toggles.yaml — o socket atende conexões em threads
# de verdade (ThreadingUnixStreamServer, não asyncio), então duas chamadas concorrentes
# (ex.: o botão "Aplicar novas configurações" do portal mandando vários toggles de uma
# vez, ou CLI + portal ao mesmo tempo) poderiam intercalar leitura/escrita e perder uma
# mudança sem isso. Lock dedicado (não db_lock) porque não protege o SQLite, só este arquivo.
_TOGGLES_LOCK = threading.Lock()

# Mesmo motivo do _TOGGLES_LOCK, mas pro read-modify-write de edge_mitigation.yaml.
_EDGE_CFG_LOCK = threading.Lock()
# idem, pro read-modify-write de flowspec_mitigation.yaml.
_FLOWSPEC_MITIGATION_CFG_LOCK = threading.Lock()

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

    def _read_conn(self):
        return _read_only_conn(self.daemon_ref.config["database"]["path"])

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
        with self._read_conn() as rconn:
            stats = storage.daemon_stats(rconn, interval)
        return {
            "ok": True, "pid": os.getpid(), "uptime_s": time.time() - d.started_at,
            "iface": d.config["capture"]["iface"], "bpf_filter": d.config["capture"]["bpf_filter"],
            "n_customers": len(d.customers), "n_whitelist": len(d.whitelist),
            "total_rows": d.total_rows,
            **stats,
        }

    def _cmd_top(self, request: dict) -> dict:
        d = self.daemon_ref
        limit = int(request.get("limit", 20))
        window_s = int(request.get("window_s") or d.config["database"]["aggregate_interval_s"])
        with self._read_conn() as rconn:
            top = storage.top_src_ips(rconn, window_s, limit)
        return {"ok": True, "top": top}

    def _cmd_client_detail(self, request: dict) -> dict:
        src_ip = request.get("src_ip")
        if not src_ip:
            return {"ok": False, "error": "src_ip obrigatório"}
        d = self.daemon_ref
        window_s = int(request.get("window_s") or d.config["database"]["aggregate_interval_s"])
        bucket_s = _bucket_for_window(window_s)
        with self._read_conn() as rconn:
            timeseries = storage.client_usage_timeseries(rconn, src_ip, window_s, bucket_s)
            top_destinations = storage.client_top_destinations(rconn, src_ip, window_s, limit=10)
        return {"ok": True, "timeseries": timeseries, "top_destinations": top_destinations}

    def _cmd_suspicious(self, request: dict) -> dict:
        resolved = bool(request.get("history", False))
        since_s = int(request.get("since_s", 86400))
        with self._read_conn() as rconn:
            items = storage.list_suspicious_clients(rconn, resolved=resolved, since_s=since_s)
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
        return self._cmd_set_toggles({"toggles": {key: request.get("value")}})

    def _cmd_set_toggles(self, request: dict) -> dict:
        """Aplica várias mudanças de toggle numa única leitura+escrita atômica — usado
        pelo botão "Aplicar novas configurações" do portal (1 requisição pra todas as
        funções marcadas, em vez de 1 por checkbox) e reaproveitado por _cmd_set_toggle
        (1 chave só) pra os dois caminhos passarem pelo mesmo lock."""
        changes = request.get("toggles")
        if not isinstance(changes, dict) or not changes:
            return {"ok": False, "error": "toggles (objeto não vazio) obrigatório"}
        d = self.daemon_ref
        path = d.config.get("feature_toggles_file", "")
        if not path:
            return {"ok": False, "error": "feature_toggles_file não configurado"}
        try:
            with _TOGGLES_LOCK:
                updated = configio.save_feature_toggles(path, changes)
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
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
        # origin permite a aba Regras unificada do portal separar por aplicação —
        # embora a regra "de verdade" viva no FlowGuard (única sessão BGP), ela foi
        # pedida pelo ClientGuard.
        payload = {"cmd": "flowspec_add", "rule": rule, "origin": "clientguard"}
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

    # --- mitigação direta na borda (SSH/ACL), sem depender do FlowGuard ------
    # Diferente de block_add/del/list (proxy pro FlowSpec via BGP do FlowGuard), isto
    # conecta via SSH/Netmiko direto no equipamento (ver edge_mitigation.py) —
    # reaproveita as credenciais já cadastradas no warmode.yaml do Modo Guerra do
    # FlowGuard, mas a técnica (ACL) e o gatilho por sinal são exclusivos do ClientGuard.

    def _flowguard_path(self) -> str:
        return self.daemon_ref.config.get("flowguard_reuse", {}).get("path", "/root/flowguard")

    def _cmd_edge_apply(self, request: dict) -> dict:
        ip = request.get("ip")
        if not ip:
            return {"ok": False, "error": "ip obrigatório"}
        d = self.daemon_ref
        ttl_s = request.get("ttl_s")
        ttl_s = int(ttl_s) if ttl_s else d.edge_cfg.get("default_ttl_s")
        signal_id = request.get("signal_id")
        return edge_mitigation.apply_and_record(
            d.conn, d.db_lock, ip, int(signal_id) if signal_id else None, ttl_s, "manual",
            d.edge_cfg, self._flowguard_path(),
        )

    def _cmd_edge_revert(self, request: dict) -> dict:
        # Despacha pelo mechanism da própria linha — mitigação flowspec precisa de
        # flowspec_del no socket do FlowGuard, não do caminho SSH/ACL legado (achado
        # real: reverter uma linha flowspec por aqui sem essa checagem fazia SSH no
        # roteador tentar desfazer uma regra de ACL que nunca existiu — "sucesso" ou
        # "Channel closed" no SSH, mas a regra FlowSpec de verdade nunca era retirada,
        # ficando ativa até o próprio TTL dela vencer, invisível pro ClientGuard).
        mitigation_id = request.get("id")
        if not mitigation_id:
            return {"ok": False, "error": "id obrigatório"}
        d = self.daemon_ref
        with d.db_lock:
            row = storage.get_edge_mitigation(d.conn, int(mitigation_id))
        if not row:
            return {"ok": False, "error": "mitigação não encontrada"}
        if row["mechanism"] == "flowspec":
            return flowspec_mitigation.revert_and_record(
                d.conn, d.db_lock, int(mitigation_id),
                d.config.get("flowguard_socket", "/var/run/flowguard.sock"),
            )
        return edge_mitigation.revert_and_record(
            d.conn, d.db_lock, int(mitigation_id), d.edge_cfg, self._flowguard_path(),
        )

    def _cmd_edge_list(self, request: dict) -> dict:
        with self._read_conn() as rconn:
            items = storage.list_edge_mitigations(rconn, active_only=bool(request.get("active_only", False)))
        return {"ok": True, "mitigations": items}

    def _cmd_edge_config(self, request: dict) -> dict:
        cfg = self.daemon_ref.edge_cfg
        return {"ok": True, "config": {
            "warmode_device": cfg.get("warmode_device", ""), "acl_number": cfg.get("acl_number"),
            "default_ttl_s": cfg.get("default_ttl_s"), "auto_mitigate": cfg.get("auto_mitigate", {}),
        }}

    def _cmd_edge_set_auto(self, request: dict) -> dict:
        changes = request.get("auto_mitigate")
        if not isinstance(changes, dict) or not changes:
            return {"ok": False, "error": "auto_mitigate (objeto não vazio) obrigatório"}
        d = self.daemon_ref
        path = d.config.get("edge_mitigation_file", edge_mitigation.DEFAULT_CONFIG_PATH)
        default_ttl_s = request.get("default_ttl_s")
        try:
            with _EDGE_CFG_LOCK:
                updated = edge_mitigation.save_auto_mitigate(
                    changes, int(default_ttl_s) if default_ttl_s else None, path,
                )
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
        d.reload_config()
        return {"ok": True, "config": {
            "auto_mitigate": updated.get("auto_mitigate", {}), "default_ttl_s": updated.get("default_ttl_s"),
        }}

    # --- mitigação via BGP FlowSpec (substitui edge_apply/edge_set_auto pra gatilho
    # automático — edge_mitigation/SSH acima fica só pra reverter mitigações legadas) --

    def _cmd_flowspec_mitigation_config(self, request: dict) -> dict:
        cfg = self.daemon_ref.flowspec_mitigation_cfg
        return {"ok": True, "config": {
            "default_ttl_s": cfg.get("default_ttl_s"), "max_active_rules": cfg.get("max_active_rules"),
            "auto_mitigate": cfg.get("auto_mitigate", {}),
        }}

    def _cmd_flowspec_mitigation_set_auto(self, request: dict) -> dict:
        changes = request.get("auto_mitigate")
        if not isinstance(changes, dict) or not changes:
            return {"ok": False, "error": "auto_mitigate (objeto não vazio) obrigatório"}
        d = self.daemon_ref
        path = d.config.get("flowspec_mitigation_file", flowspec_mitigation.DEFAULT_CONFIG_PATH)
        default_ttl_s = request.get("default_ttl_s")
        try:
            with _FLOWSPEC_MITIGATION_CFG_LOCK:
                updated = flowspec_mitigation.save_auto_mitigate(
                    changes, int(default_ttl_s) if default_ttl_s else None, path,
                )
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
        d.reload_config()
        return {"ok": True, "config": {
            "auto_mitigate": updated.get("auto_mitigate", {}), "default_ttl_s": updated.get("default_ttl_s"),
        }}

    def _cmd_reload(self, request: dict) -> dict:
        self.daemon_ref.reload_config()
        return {"ok": True}

    def _cmd_stop(self, request: dict) -> dict:
        threading.Timer(0.2, self.daemon_ref.stop).start()
        return {"ok": True, "message": "encerrando..."}
