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
import escalation
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
# idem, pro read-modify-write de detection_templates.yaml / detection_overrides.yaml.
_DETECTION_TEMPLATES_LOCK = threading.Lock()
_DETECTION_OVERRIDES_LOCK = threading.Lock()
# idem, pro read-modify-write de escalation.yaml.
_ESCALATION_CFG_LOCK = threading.Lock()

# Cache curto de storage.top_src_ips (achado real, profiling de CPU 2026-07-10:
# sozinho respondia por ~52% da CPU do daemon — GROUP BY sem filtro de src_ip
# sobre client_flow_aggs, chamado de novo a cada abertura de aba/troca de janela
# no portal, às vezes de várias sessões de browser quase ao mesmo tempo pedindo
# EXATAMENTE a mesma (window_s, limit)). TTL curto (não muda o comportamento
# visível — ninguém precisa de um ranking atualizado a cada segundo — só absorve
# chamadas duplicadas próximas no tempo).
_TOP_CACHE_LOCK = threading.Lock()
_TOP_CACHE: dict[tuple, tuple[float, list]] = {}
_TOP_CACHE_TTL_S = 20.0

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
    "# Editável diretamente, via clientguard-cli customers add|del|edit, ou pelo portal\n"
    "# (aba ClientGuard > Configurações > Redes de Clientes).\n"
    "#\n"
    "# client_multiplier: quantas identidades reais um único src_ip visível desse prefixo pode\n"
    "# representar combinadas (ex.: pool de CGNAT PÓS-NAT, onde 1 IP público externo = várias\n"
    "# pessoas atrás do NAT). detector.py escala os limiares de volume/diversidade por esse\n"
    "# fator pra não confundir tráfego combinado de várias pessoas com o comportamento de 1\n"
    "# cliente só. Sem o campo (ou valor 1), nenhum ajuste é aplicado.\n"
    "#\n"
    "# template: perfil de limiar de detecção (ver detection_templates.yaml) — 'cgnat' pra\n"
    "# pools com muitos clientes ativos e tráfego residencial diverso (torrent/jogos/VoIP,\n"
    "# PRÉ ou PÓS-NAT — não precisa de client_multiplier se o NetFlow já captura o IP\n"
    "# pré-NAT, 1 IP = 1 cliente real), 'cdn' pra infraestrutura própria (core, relay/TURN,\n"
    "# cache) com fan-out extremo esperado. Sem o campo, o prefixo usa o limiar global de\n"
    "# detection.* em config.yaml."
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
        with self._read_conn() as rconn:
            stats = storage.daemon_stats(rconn)
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
        cache_key = (window_s, limit)
        now = time.time()
        with _TOP_CACHE_LOCK:
            cached = _TOP_CACHE.get(cache_key)
            if cached is not None and now - cached[0] < _TOP_CACHE_TTL_S:
                return {"ok": True, "top": cached[1]}
        with self._read_conn() as rconn:
            top = storage.top_src_ips(rconn, window_s, limit)
        with _TOP_CACHE_LOCK:
            _TOP_CACHE[cache_key] = (now, top)
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

    def _cmd_network_series(self, request: dict) -> dict:
        customer_prefix = request.get("customer_prefix")
        if not customer_prefix:
            return {"ok": False, "error": "customer_prefix obrigatório"}
        d = self.daemon_ref
        window_s = int(request.get("window_s") or d.config["database"]["aggregate_interval_s"])
        bucket_s = _bucket_for_window(window_s)
        with self._read_conn() as rconn:
            timeseries = storage.network_usage_timeseries(rconn, customer_prefix, window_s, bucket_s)
        return {"ok": True, "timeseries": timeseries}

    def _cmd_suspicious(self, request: dict) -> dict:
        resolved = bool(request.get("history", False))
        since_s = int(request.get("since_s", 86400))
        with self._read_conn() as rconn:
            items = storage.list_suspicious_clients(rconn, resolved=resolved, since_s=since_s)
            # "esse cliente já participa de alguma mitigação, e está em vigor
            # agora?" — pedido do usuário na aba Sinais Suspeitos do portal.
            # Última mitigação (qualquer status), não só a ativa: sinaliza tanto
            # "mitigado agora" quanto "já teve mitigação, mas não está mais em
            # vigor" (achado real de auditoria: essa segunda situação é
            # exatamente o gap que a reconciliação com o FlowGuard existe pra
            # corrigir — ver flowspec_mitigation.reconcile_with_flowguard).
            for item in items:
                mitigation = storage.get_latest_edge_mitigation(rconn, item["src_ip"])
                item["mitigation"] = {
                    "status": mitigation["status"], "mechanism": mitigation["mechanism"],
                    "trigger_type": mitigation["trigger_type"], "ts_applied": mitigation["ts_applied"],
                    "ts_expires": mitigation["ts_expires"],
                } if mitigation else None
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

    def _customers_entry_from_request(self, request: dict) -> tuple[dict | None, str]:
        """Monta os campos opcionais (name/client_multiplier/template) comuns a
        customers_add/customers_edit, com a mesma validação nos dois — template
        precisa existir em detection_templates.yaml (erro claro em vez de silenciosamente
        cair no limiar global por um nome digitado errado)."""
        entry: dict = {}
        if request.get("name"):
            entry["name"] = request["name"]
        if "client_multiplier" in request and request["client_multiplier"] not in (None, ""):
            try:
                multiplier = int(request["client_multiplier"])
            except (TypeError, ValueError):
                return None, "client_multiplier deve ser um inteiro"
            if multiplier < 1:
                return None, "client_multiplier deve ser >= 1"
            entry["client_multiplier"] = multiplier
        if "template" in request and request["template"]:
            template_name = request["template"]
            if template_name not in self.daemon_ref.detection_templates:
                return None, f"template '{template_name}' não existe"
            entry["template"] = template_name
        return entry, ""

    def _cmd_customers_add(self, request: dict) -> dict:
        network = request.get("network")
        prefix = request.get("prefix")
        if not network or not prefix:
            return {"ok": False, "error": "network e prefix obrigatórios"}
        try:
            ipaddress.ip_network(network, strict=False)
        except ValueError:
            return {"ok": False, "error": f"network inválida: {network}"}
        extra, err = self._customers_entry_from_request(request)
        if err:
            return {"ok": False, "error": err}
        d = self.daemon_ref
        path = d.config["customer_registry"]
        items = configio.load_yaml_list(path)
        if any(entry.get("network") == network for entry in items):
            return {"ok": False, "error": "network já cadastrada"}
        entry = {"network": network, "prefix": prefix, **extra}
        items.append(entry)
        configio.save_yaml_list(path, items, header_comment=CUSTOMERS_HEADER)
        d.reload_config()
        return {"ok": True}

    def _cmd_customers_edit(self, request: dict) -> dict:
        """Atualiza name/client_multiplier/template de uma network JÁ cadastrada, sem
        precisar del+add (que perderia o histórico de ordem no arquivo e exigiria
        redigitar network/prefix). Passar client_multiplier/template vazio ("" ou null)
        REMOVE o campo — volta pro comportamento sem ajuste (multiplier=1, sem template)."""
        network = request.get("network")
        if not network:
            return {"ok": False, "error": "network obrigatória"}
        extra, err = self._customers_entry_from_request(request)
        if err:
            return {"ok": False, "error": err}
        d = self.daemon_ref
        path = d.config["customer_registry"]
        items = configio.load_yaml_list(path)
        entry = next((e for e in items if e.get("network") == network), None)
        if entry is None:
            return {"ok": False, "error": "network não cadastrada"}
        for key in ("name", "client_multiplier", "template"):
            if key in request:
                if key in extra:
                    entry[key] = extra[key]
                else:
                    entry.pop(key, None)
        configio.save_yaml_list(path, items, header_comment=CUSTOMERS_HEADER)
        d.reload_config()
        return {"ok": True, "entry": entry}

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
        # pedida pelo ClientGuard. peer="pppoe": achado real de revisão — sem isso
        # caía no default 'main', que nunca vê o IP pré-NAT do cliente (mesmo bug
        # que já tinha sido corrigido pro caminho automático em flowspec_mitigation.py,
        # mas ficou pra trás aqui no bloqueio manual).
        payload = {"cmd": "flowspec_add", "rule": rule, "origin": "clientguard", "peer": "pppoe"}
        ttl_s = request.get("ttl_s")
        if ttl_s:
            payload["ttl_s"] = int(ttl_s)
        resp = control.send_command(self._fg_socket(), payload)
        # Achado real de revisão: este caminho manual nunca passava pela exceção de
        # PBR (flowspec_mitigation.push_pbr_bypass) — só a mitigação automática dos
        # detectores era coberta. Sem isso, um bloqueio manual "aplicava" mas o PBR
        # da caixa PPPoE continuava redirecionando o cliente pro A10 antes do
        # FlowSpec agir, do jeito exato que motivou a correção inteira.
        if resp.get("ok") and resp.get("rule_id") is not None:
            bypass_result = flowspec_mitigation.push_pbr_bypass(
                rule, resp["rule_id"], self.daemon_ref.flowspec_mitigation_cfg, self._flowguard_path())
            if not bypass_result.get("ok") and not bypass_result.get("skipped"):
                LOG.error("bloqueio manual de %s: FlowSpec anunciado mas exceção de PBR falhou: %s",
                          ip, bypass_result.get("error"))
                resp = {**resp, "pbr_bypass_error": bypass_result.get("error")}
        return resp

    def _cmd_block_del(self, request: dict) -> dict:
        rule_id = request.get("id")
        if not rule_id:
            return {"ok": False, "error": "id obrigatório"}
        resp = control.send_command(self._fg_socket(), {"cmd": "flowspec_del", "rule_id": rule_id})
        # Espelha a limpeza da exceção de PBR — sem isso, bloqueios manuais removidos
        # pelo botão "Remover" deixariam a entrada na ACL 3001 órfã pra sempre (só a
        # expiração por TTL do FlowSpec/expire_due sabe reverter mitigações
        # automáticas; um bloqueio manual apagado explicitamente não passava por
        # nenhum dos dois). Não sabemos o src_ip aqui (só o id da regra) — usamos
        # "-" só pro registro de auditoria, a remoção em si é por rule_id.
        if resp.get("ok"):
            bypass_result = flowspec_mitigation.remove_pbr_bypass(
                int(rule_id), "-", self.daemon_ref.flowspec_mitigation_cfg, self._flowguard_path())
            if not bypass_result.get("ok") and not bypass_result.get("skipped"):
                LOG.error("remoção manual de bloqueio (regra %s): exceção de PBR não removida: %s",
                          rule_id, bypass_result.get("error"))
        return resp

    def _cmd_block_list(self, request: dict) -> dict:
        resp = control.send_command(self._fg_socket(), {"cmd": "rules"})
        if not resp.get("ok"):
            return resp
        # só regras de bloqueio por origem (discard/rate-limit) — RTBH é o
        # mecanismo de proteção de vítima do FlowGuard, não bloqueio de cliente.
        # Bug real corrigido aqui: faltava filtrar por origin=="clientguard" —
        # sem isso, a lista misturava bloqueios manuais do FlowGuard e mitigações
        # automáticas do próprio ClientGuard (port_scan etc.) junto com bloqueios
        # manuais de cliente, todos com o mesmo rótulo "bloqueio".
        blocks = [
            r for r in resp.get("rules", [])
            if r.get("src_prefix") and r.get("action") != "rtbh" and r.get("origin") == "clientguard"
        ]
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

    def _revert_edge_mitigation_row(self, row: dict) -> dict:
        # Despacha pelo mechanism da própria linha — mitigação flowspec precisa de
        # flowspec_del no socket do FlowGuard, não do caminho SSH/ACL legado (achado
        # real: reverter uma linha flowspec por aqui sem essa checagem fazia SSH no
        # roteador tentar desfazer uma regra de ACL que nunca existiu — "sucesso" ou
        # "Channel closed" no SSH, mas a regra FlowSpec de verdade nunca era retirada,
        # ficando ativa até o próprio TTL dela vencer, invisível pro ClientGuard).
        d = self.daemon_ref
        if row["mechanism"] == "flowspec":
            return flowspec_mitigation.revert_and_record(
                d.conn, d.db_lock, row["id"],
                d.config.get("flowguard_socket", "/var/run/flowguard.sock"),
                d.flowspec_mitigation_cfg, self._flowguard_path(),
            )
        return edge_mitigation.revert_and_record(
            d.conn, d.db_lock, row["id"], d.edge_cfg, self._flowguard_path(),
        )

    def _cmd_edge_revert(self, request: dict) -> dict:
        mitigation_id = request.get("id")
        if not mitigation_id:
            return {"ok": False, "error": "id obrigatório"}
        d = self.daemon_ref
        with d.db_lock:
            row = storage.get_edge_mitigation(d.conn, int(mitigation_id))
        if not row:
            return {"ok": False, "error": "mitigação não encontrada"}
        return self._revert_edge_mitigation_row(row)

    def _cmd_edge_revert_all(self, request: dict) -> dict:
        d = self.daemon_ref
        with d.db_lock:
            rows = storage.list_edge_mitigations(d.conn, active_only=True)
        reverted, failed = 0, 0
        for row in rows:
            resp = self._revert_edge_mitigation_row(row)
            if resp.get("ok"):
                reverted += 1
            else:
                failed += 1
                LOG.error("falha ao reverter mitigação id=%s: %s", row["id"], resp.get("error"))
        return {"ok": failed == 0, "reverted": reverted, "failed": failed}

    def _cmd_edge_list(self, request: dict) -> dict:
        with self._read_conn() as rconn:
            items = storage.list_edge_mitigations(rconn, active_only=bool(request.get("active_only", False)))
        # pedido do usuário: aba Regras mostrar em qual equipamento cada mitigação
        # está sendo aplicada. mechanism='ssh' usa sempre o mesmo equipamento
        # (edge_mitigation.yaml.warmode_device, único ACL global); mechanism=
        # 'flowspec' sempre vai pro peer 'pppoe' do FlowGuard (achado real de bug
        # já documentado em flowspec_mitigation.py) — reaproveita o nome já
        # configurado em flowspec_mitigation.yaml.pbr_bypass.warmode_device, sem
        # precisar duplicar config nem perguntar ao FlowGuard.
        ssh_device = self.daemon_ref.edge_cfg.get("warmode_device", "")
        flowspec_device = self.daemon_ref.flowspec_mitigation_cfg.get("pbr_bypass", {}).get("warmode_device", "")
        for item in items:
            item["device_name"] = ssh_device if item["mechanism"] == "ssh" else (flowspec_device or "pppoe")
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

    # --- bloqueio progressivo por reincidência (comum aos 7 detectores) -------------

    def _cmd_escalation_config(self, request: dict) -> dict:
        return {"ok": True, "escalation": self.daemon_ref.escalation_cfg}

    def _cmd_escalation_set_config(self, request: dict) -> dict:
        changes = request.get("changes")
        if not isinstance(changes, dict) or not changes:
            return {"ok": False, "error": "changes (objeto não vazio) obrigatório"}
        d = self.daemon_ref
        path = d.config.get("escalation_file", escalation.DEFAULT_CONFIG_PATH)
        try:
            with _ESCALATION_CFG_LOCK:
                updated = escalation.save_config(changes, path)
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
        d.reload_config()
        return {"ok": True, "escalation": updated}

    # --- ajuste fino dos limiares de detecção (detection.* de config.yaml) e dos
    # templates de perfil de rede (cgnat/cdn, ver detection_templates.yaml) ---------

    def _cmd_detection_cfg(self, request: dict) -> dict:
        return {"ok": True, "detection": self.daemon_ref.config["detection"]}

    def _cmd_detection_cfg_set(self, request: dict) -> dict:
        changes = request.get("changes")
        if not isinstance(changes, dict) or not changes:
            return {"ok": False, "error": "changes (objeto não vazio) obrigatório"}
        d = self.daemon_ref
        path = d.config.get("detection_overrides_file", configio.DEFAULT_DETECTION_OVERRIDES_PATH)
        try:
            with _DETECTION_OVERRIDES_LOCK:
                configio.save_detection_overrides(path, changes)
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
        d.reload_config()
        return {"ok": True, "detection": d.config["detection"]}

    def _cmd_detection_templates(self, request: dict) -> dict:
        return {"ok": True, "templates": self.daemon_ref.detection_templates}

    def _cmd_detection_templates_set(self, request: dict) -> dict:
        name = (request.get("name") or "").strip()
        values = request.get("values")
        if not name or not isinstance(values, dict) or not values:
            return {"ok": False, "error": "name e values (objeto não vazio) obrigatórios"}
        d = self.daemon_ref
        path = d.config.get("detection_templates_file", configio.DEFAULT_DETECTION_TEMPLATES_PATH)
        try:
            with _DETECTION_TEMPLATES_LOCK:
                updated = configio.save_detection_template(path, name, values, request.get("description", ""))
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
        d.reload_config()
        return {"ok": True, "templates": updated}

    def _cmd_detection_templates_del(self, request: dict) -> dict:
        name = (request.get("name") or "").strip()
        if not name:
            return {"ok": False, "error": "name obrigatório"}
        d = self.daemon_ref
        path = d.config.get("detection_templates_file", configio.DEFAULT_DETECTION_TEMPLATES_PATH)
        try:
            with _DETECTION_TEMPLATES_LOCK:
                updated = configio.delete_detection_template(path, name)
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
        d.reload_config()
        return {"ok": True, "templates": updated}

    def _cmd_reload(self, request: dict) -> dict:
        self.daemon_ref.reload_config()
        return {"ok": True}

    def _cmd_stop(self, request: dict) -> dict:
        threading.Timer(0.2, self.daemon_ref.stop).start()
        return {"ok": True, "message": "encerrando..."}
