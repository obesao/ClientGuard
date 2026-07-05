#!/root/clientguard/venv/bin/python3
"""clientguard-cli — cliente de terminal para o ClientGuard (status, clientes suspeitos,
whitelist, cadastro de clientes, monitor interativo)."""

from __future__ import annotations

import argparse
import json
import socket
import sys
import time

import yaml
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

import configio
import edge_mitigation

DEFAULT_CONFIG_PATH = "/root/clientguard/config.yaml"
DEFAULT_SOCKET_PATH = "/var/run/clientguard.sock"

console = Console()

SIGNAL_LABELS = {
    "port_scan_horizontal": "scan horizontal",
    "port_scan_vertical": "scan vertical",
    "amplifier_hosted": "amplificador hospedado",
    "spam_bot": "spam bot",
    "malicious_contact": "contato com IP malicioso conhecido",
    "coordinated_destination": "destino coordenado (múltiplos clientes)",
    "dns_tunneling": "túnel DNS / exfiltração via DNS",
}


DEFAULT_FLOWGUARD_SOCKET_PATH = "/var/run/flowguard.sock"


def resolve_socket_path(config_path: str) -> str:
    try:
        with open(config_path, "r", encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh)
        return cfg["daemon"]["socket"]
    except (OSError, KeyError, TypeError):
        return DEFAULT_SOCKET_PATH


def resolve_flowguard_socket_path(config_path: str) -> str:
    """BGP é gerenciado pelo FlowGuard (ExaBGP), não pelo ClientGuard — só consultamos
    o status via socket dele, sem nenhum código/config compartilhado além disso."""
    try:
        with open(config_path, "r", encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh)
        return cfg.get("flowguard_socket") or DEFAULT_FLOWGUARD_SOCKET_PATH
    except OSError:
        return DEFAULT_FLOWGUARD_SOCKET_PATH


def fetch_bgp_status(fg_sock_path: str) -> dict:
    resp = send_command(fg_sock_path, {"cmd": "bgp_status"}, timeout=1.5)
    if not resp.get("ok"):
        return {"peer_state": "down", "detail": resp.get("error", "FlowGuard indisponível")}
    return resp


def fmt_bgp_state(bgp: dict) -> str:
    if bgp.get("peer_state") == "up":
        return "[bold green]Up[/bold green]"
    return "[bold red]Down/Idle[/bold red]"


def send_command(sock_path: str, payload: dict, timeout: float = 6.0) -> dict:
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(sock_path)
            sock.sendall((json.dumps(payload) + "\n").encode("utf-8"))
            sock.shutdown(socket.SHUT_WR)
            chunks = []
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
        data = b"".join(chunks).decode("utf-8").strip()
        return json.loads(data) if data else {"ok": False, "error": "resposta vazia do daemon"}
    except FileNotFoundError:
        return {"ok": False, "error": f"socket não encontrado em {sock_path} — o daemon está rodando?"}
    except ConnectionRefusedError:
        return {"ok": False, "error": "conexão recusada — daemon não está escutando no socket"}
    except PermissionError:
        return {"ok": False, "error": "permissão negada ao acessar o socket (rode como root)"}
    except socket.timeout:
        return {"ok": False, "error": "timeout ao falar com o daemon"}
    except json.JSONDecodeError:
        return {"ok": False, "error": "resposta inválida do daemon"}


def fmt_bytes(n: float) -> str:
    n = float(n)
    if n >= 1e9:
        return f"{n / 1e9:.2f} GB"
    if n >= 1e6:
        return f"{n / 1e6:.1f} MB"
    if n >= 1e3:
        return f"{n / 1e3:.0f} KB"
    return f"{n:.0f} B"


def fmt_ts(ts: int) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def die_on_error(resp: dict) -> None:
    if not resp.get("ok"):
        console.print(f"[red]Erro:[/red] {resp.get('error', 'desconhecido')}")
        sys.exit(1)


def _print_simple(resp: dict, ok_message: str = "ok") -> None:
    if resp.get("ok"):
        console.print(f"[green]{ok_message}[/green]")
    else:
        console.print(f"[red]Erro:[/red] {resp.get('error', 'desconhecido')}")
        sys.exit(1)


# --- subcomandos ---------------------------------------------------------

def cmd_status(args: argparse.Namespace, sock_path: str) -> None:
    resp = send_command(sock_path, {"cmd": "status"})
    die_on_error(resp)
    table = Table(title="ClientGuard — Status do Daemon", show_header=False)
    table.add_row("PID", str(resp["pid"]))
    table.add_row("Uptime", f"{resp['uptime_s']:.0f}s")
    table.add_row("Captura", f"{resp['iface']} ({resp['bpf_filter']})")
    table.add_row("Flows na janela atual", str(resp["flows_window"]))
    table.add_row("Clientes ativos na janela", str(resp["distinct_src_ips"]))
    table.add_row("Total de agregados no banco", str(resp["total_rows"]))
    table.add_row("Sinais suspeitos abertos", str(resp["open_signals"]))
    table.add_row("Clientes cadastrados", str(resp["n_customers"]))
    table.add_row("IPs na whitelist", str(resp["n_whitelist"]))
    bgp = fetch_bgp_status(resolve_flowguard_socket_path(args.config))
    bgp_line = fmt_bgp_state(bgp)
    if bgp.get("peer_ip"):
        bgp_line += f"  ({bgp['peer_ip']})"
    table.add_row("BGP (FlowGuard/ExaBGP)", bgp_line)
    console.print(table)


def cmd_top(args: argparse.Namespace, sock_path: str) -> None:
    resp = send_command(sock_path, {"cmd": "top", "limit": args.limit, "window_s": args.window_s})
    die_on_error(resp)
    table = Table(title=f"Top {args.limit} Clientes por Tráfego (últimos {args.window_s}s)")
    table.add_column("src_ip")
    table.add_column("Cliente")
    table.add_column("Tráfego", justify="right")
    table.add_column("Flows", justify="right")
    for row in resp["top"]:
        table.add_row(row["src_ip"], row["customer_prefix"] or "-", fmt_bytes(row["bytes"]), str(row["flows"]))
    if not resp["top"]:
        console.print("[green]Nenhum tráfego na janela.[/green]")
    else:
        console.print(table)


_MITIGATION_MECHANISM_LABELS = {"flowspec": "FlowSpec", "ssh": "SSH/ACL"}


def _fmt_duration(seconds: int) -> str:
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m{seconds % 60:02d}s"
    return f"{seconds // 3600}h{(seconds % 3600) // 60:02d}m"


# pedido do usuário: "aberto" sozinho não diz se está REALMENTE acontecendo
# agora — um sinal fica "aberto" enquanto a condição continuar batendo
# (correto), mas nada avisava quando isso já tinha parado há muito tempo e o
# registro só ainda não resolveu sozinho (ver resolve_stale_signals, que só
# resolve depois de horas sem reconfirmação). ts_last_seen é atualizado a cada
# ciclo em que o detector re-confirma a condição; janela "fresca" de 90s cobre
# ~3 ciclos de agregação (30s padrão), com folga pra jitter.
_ACTIVITY_FRESH_WINDOW_S = 90


def _fmt_activity_freshness(ts_last_seen: int | None, row_open: bool) -> str:
    if not row_open or not ts_last_seen:
        return "-"
    age_s = int(time.time()) - ts_last_seen
    if age_s < _ACTIVITY_FRESH_WINDOW_S:
        return "[green]🟢 em andamento[/green]"
    return f"[yellow]🟡 sem atividade há {_fmt_duration(age_s)}[/yellow]"


def _fmt_mitigation_cell(mitigation: dict | None, row_open: bool = False) -> str:
    if not mitigation:
        return "[dim]sem mitigação[/dim]"
    mechanism = _MITIGATION_MECHANISM_LABELS.get(mitigation["mechanism"], mitigation["mechanism"])
    if mitigation["status"] == "active":
        return f"[green]🛡 ativa ({mechanism})[/green]"
    if mitigation["status"] == "failed":
        return f"[red]falhou ({mechanism})[/red]"
    # sinal ainda aberto (resolved=0) com mitigação já encerrada = cliente SEM
    # proteção agora, não é só histórico — pedido do usuário pra deixar isso claro
    if row_open:
        return f"[red]⚠ sem proteção ({mechanism})[/red]"
    return f"[dim]encerrada ({mechanism})[/dim]"  # reverted (TTL vencido, manual, ou reconciliação)


def cmd_suspicious(args: argparse.Namespace, sock_path: str) -> None:
    resp = send_command(sock_path, {"cmd": "suspicious", "history": args.history, "since_s": args.since_s})
    die_on_error(resp)
    title = "Sinais Resolvidos" if args.history else "Sinais Suspeitos Abertos"
    table = Table(title=title)
    table.add_column("ID")
    table.add_column("src_ip")
    table.add_column("Cliente")
    table.add_column("Sinal")
    table.add_column("Confiança", justify="right")
    table.add_column("Detectado em")
    table.add_column("Última vez")
    table.add_column("Atividade")
    table.add_column("Mitigação")
    for row in resp["suspicious"]:
        row_open = not row.get("resolved")
        table.add_row(
            str(row["id"]), row["src_ip"], row["customer_prefix"] or "-",
            SIGNAL_LABELS.get(row["signal_type"], row["signal_type"]),
            f"{(row['confidence'] or 0) * 100:.0f}%", fmt_ts(row["ts_detected"]), fmt_ts(row["ts_last_seen"]),
            _fmt_activity_freshness(row.get("ts_last_seen"), row_open),
            _fmt_mitigation_cell(row.get("mitigation"), row_open),
        )
    if not resp["suspicious"]:
        console.print(f"[green]{title}: nenhum registro.[/green]")
        return
    console.print(table)
    for row in resp["suspicious"]:
        if row.get("ai_explanation"):
            console.print(Panel(row["ai_explanation"], title=f"IA — sinal {row['id']} ({row['src_ip']})"))


def cmd_resolve(args: argparse.Namespace, sock_path: str) -> None:
    resp = send_command(sock_path, {"cmd": "resolve", "id": args.id})
    _print_simple(resp, ok_message=f"sinal {args.id} marcado como resolvido")


def cmd_clear_suspicious(args: argparse.Namespace, sock_path: str) -> None:
    resp = send_command(sock_path, {"cmd": "clear_suspicious"})
    die_on_error(resp)
    console.print(f"[green]{resp['cleared']} sinal(is) suspeito(s) marcado(s) como resolvido.[/green]")


def cmd_toggles_list(args: argparse.Namespace, sock_path: str) -> None:
    resp = send_command(sock_path, {"cmd": "toggles"})
    die_on_error(resp)
    table = Table(title="Funções do ClientGuard")
    table.add_column("Função")
    table.add_column("Estado")
    for key, value in resp["toggles"].items():
        table.add_row(key, "[green]habilitado[/green]" if value else "[red]desabilitado[/red]")
    console.print(table)


def cmd_toggles_set(args: argparse.Namespace, sock_path: str) -> None:
    resp = send_command(sock_path, {"cmd": "set_toggle", "key": args.key, "value": args.value == "on"})
    _print_simple(resp, ok_message=f"{args.key} = {args.value}")


def cmd_whitelist_add(args: argparse.Namespace, sock_path: str) -> None:
    resp = send_command(sock_path, {"cmd": "whitelist_add", "ip": args.ip})
    _print_simple(resp)


def cmd_whitelist_del(args: argparse.Namespace, sock_path: str) -> None:
    resp = send_command(sock_path, {"cmd": "whitelist_del", "ip": args.ip})
    _print_simple(resp)


def cmd_customers_add(args: argparse.Namespace, sock_path: str) -> None:
    resp = send_command(sock_path, {
        "cmd": "customers_add", "network": args.network, "prefix": args.prefix, "name": args.name,
    })
    _print_simple(resp)


def cmd_customers_del(args: argparse.Namespace, sock_path: str) -> None:
    resp = send_command(sock_path, {"cmd": "customers_del", "network": args.network})
    _print_simple(resp)


def cmd_block_add(args: argparse.Namespace, sock_path: str) -> None:
    resp = send_command(sock_path, {"cmd": "block_add", "ip": args.ip, "ttl_s": args.ttl_s})
    _print_simple(resp, ok_message=f"{args.ip} bloqueado via FlowSpec (regra id={resp.get('rule_id')})")


def cmd_block_del(args: argparse.Namespace, sock_path: str) -> None:
    resp = send_command(sock_path, {"cmd": "block_del", "id": args.id})
    _print_simple(resp, ok_message=f"regra {args.id} removida")


def cmd_block_list(args: argparse.Namespace, sock_path: str) -> None:
    resp = send_command(sock_path, {"cmd": "block_list"})
    die_on_error(resp)
    table = Table(title="IPs Bloqueados (FlowSpec via FlowGuard)")
    table.add_column("ID")
    table.add_column("Origem bloqueada")
    table.add_column("Ação")
    table.add_column("Equipamento")
    table.add_column("Gatilho")
    table.add_column("Expira em")
    now = time.time()
    for row in resp["blocks"]:
        ttl = max(0, int(row["expires_at"] - now))
        trigger = "automático" if row.get("trigger_type") == "auto" else "manual"
        table.add_row(str(row["id"]), row["src_prefix"], row["action"], row.get("device_name") or "-",
                      trigger, f"{ttl}s")
    if not resp["blocks"]:
        console.print("[green]Nenhum IP bloqueado no momento.[/green]")
    else:
        console.print(table)


def cmd_edge_apply(args: argparse.Namespace, sock_path: str) -> None:
    # timeout maior que o default (6s) — isso conecta via SSH de verdade e roda
    # send_config_set num equipamento real, pode levar bem mais que 6s (mesmo
    # timeout já usado pelo CGI do portal pra essa mesma ação)
    resp = send_command(sock_path, {"cmd": "edge_apply", "ip": args.ip, "ttl_s": args.ttl_s}, timeout=25.0)
    if resp.get("ok") and resp.get("already_active"):
        _print_simple(resp, ok_message=f"{args.ip} já tinha mitigação ativa (TTL renovado)")
    else:
        _print_simple(resp, ok_message=f"{args.ip} bloqueado direto na borda (mitigação id={resp.get('id')})")


def cmd_edge_revert(args: argparse.Namespace, sock_path: str) -> None:
    resp = send_command(sock_path, {"cmd": "edge_revert", "id": args.id}, timeout=25.0)
    _print_simple(resp, ok_message=f"mitigação {args.id} revertida")


def cmd_edge_list(args: argparse.Namespace, sock_path: str) -> None:
    resp = send_command(sock_path, {"cmd": "edge_list", "active_only": args.active_only})
    die_on_error(resp)
    table = Table(title="Mitigações Diretas na Borda (SSH/ACL + FlowSpec)")
    table.add_column("ID")
    table.add_column("src_ip")
    table.add_column("Mecanismo")
    table.add_column("Equipamento")
    table.add_column("Status")
    table.add_column("Gatilho")
    table.add_column("Aplicada em")
    table.add_column("Expira em")
    now = time.time()
    _mechanism_labels = {"ssh": "SSH/ACL", "flowspec": "FlowSpec"}
    for row in resp["mitigations"]:
        ttl = f"{max(0, int(row['ts_expires'] - now))}s" if row.get("ts_expires") else "sem TTL"
        table.add_row(str(row["id"]), row["src_ip"], _mechanism_labels.get(row["mechanism"], row["mechanism"]),
                      row.get("device_name") or "-", row["status"], row["trigger_type"],
                      fmt_ts(row["ts_applied"]), ttl if row["status"] == "active" else "-")
    if not resp["mitigations"]:
        console.print("[green]Nenhuma mitigação de borda registrada.[/green]")
    else:
        console.print(table)


def cmd_edge_auto_list(args: argparse.Namespace, sock_path: str) -> None:
    resp = send_command(sock_path, {"cmd": "edge_config"})
    die_on_error(resp)
    cfg = resp["config"]
    table = Table(title="Gatilho automático — mitigação direta na borda")
    table.add_column("Detector")
    table.add_column("Estado")
    for key, value in cfg["auto_mitigate"].items():
        table.add_row(key, "[green]habilitado[/green]" if value else "[red]desabilitado[/red]")
    console.print(table)
    console.print(f"TTL padrão: {cfg['default_ttl_s']}s  |  equipamento: {cfg['warmode_device'] or '(não configurado)'}")


def cmd_edge_auto_set(args: argparse.Namespace, sock_path: str) -> None:
    resp = send_command(sock_path, {"cmd": "edge_set_auto", "auto_mitigate": {args.detector: args.value == "on"}})
    _print_simple(resp, ok_message=f"auto-mitigação de borda: {args.detector} = {args.value}")


def cmd_reload(args: argparse.Namespace, sock_path: str) -> None:
    resp = send_command(sock_path, {"cmd": "reload"})
    _print_simple(resp, ok_message="config recarregado (clientes e whitelist)")


def cmd_stop(args: argparse.Namespace, sock_path: str) -> None:
    resp = send_command(sock_path, {"cmd": "stop"})
    _print_simple(resp, ok_message="sinal de parada enviado ao daemon")


# --- modo interativo -------------------------------------------------------

def build_dashboard(sock_path: str, fg_sock_path: str) -> Group:
    status = send_command(sock_path, {"cmd": "status"})
    now_str = time.strftime("%Y-%m-%d %H:%M:%S")
    if not status.get("ok"):
        header = Panel(f"[red]Daemon indisponível: {status.get('error')}[/red]", title="ClientGuard Monitor")
        return Group(header)

    top = send_command(sock_path, {"cmd": "top", "limit": 10})
    suspicious = send_command(sock_path, {"cmd": "suspicious"})
    bgp = fetch_bgp_status(fg_sock_path)

    statusbar = (
        f"Flows/janela: [bold]{status['flows_window']}[/bold]  |  "
        f"Clientes ativos: [bold]{status['distinct_src_ips']}[/bold]  |  "
        f"Sinais abertos: [bold red]{status['open_signals']}[/bold red]  |  "
        f"Cadastrados: [bold]{status['n_customers']}[/bold]  |  "
        f"Whitelist: [bold]{status['n_whitelist']}[/bold]  |  "
        f"BGP: {fmt_bgp_state(bgp)}  |  Daemon: [green]OK[/green]"
    )
    header = Panel(statusbar, title=f"ClientGuard Monitor  |  {now_str}  |  Ctrl+C para sair")

    top_table = Table(title="Top Clientes por Tráfego")
    top_table.add_column("src_ip")
    top_table.add_column("Cliente")
    top_table.add_column("Tráfego", justify="right")
    for row in top.get("top", []):
        top_table.add_row(row["src_ip"], row["customer_prefix"] or "-", fmt_bytes(row["bytes"]))
    if not top.get("top"):
        top_table.add_row("-", "-", "[green]sem tráfego[/green]")

    suspicious_table = Table(title="Sinais Suspeitos Abertos")
    suspicious_table.add_column("src_ip")
    suspicious_table.add_column("Cliente")
    suspicious_table.add_column("Sinal")
    suspicious_table.add_column("Confiança", justify="right")
    for row in suspicious.get("suspicious", []):
        suspicious_table.add_row(
            row["src_ip"], row["customer_prefix"] or "-",
            SIGNAL_LABELS.get(row["signal_type"], row["signal_type"]),
            f"{(row['confidence'] or 0) * 100:.0f}%",
        )
    if not suspicious.get("suspicious"):
        suspicious_table.add_row("-", "-", "[green]nenhum[/green]", "-")

    return Group(header, top_table, suspicious_table)


def run_interactive(sock_path: str, fg_sock_path: str, interval: float) -> None:
    try:
        with Live(build_dashboard(sock_path, fg_sock_path), console=console, screen=True, auto_refresh=False) as live:
            while True:
                time.sleep(interval)
                live.update(build_dashboard(sock_path, fg_sock_path), refresh=True)
    except KeyboardInterrupt:
        pass


# --- main --------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="clientguard-cli — cliente de terminal do ClientGuard")
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH)
    parser.add_argument("--socket", default=None, help="sobrescreve o caminho do socket")
    parser.add_argument("--interval", type=float, default=2.0,
                         help="intervalo de atualização do monitor interativo, em segundos (padrão: 2.0)")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("status").set_defaults(func=cmd_status)

    p_top = sub.add_parser("top")
    p_top.add_argument("--limit", type=int, default=20)
    p_top.add_argument("--window-s", type=int, default=30)
    p_top.set_defaults(func=cmd_top)

    p_suspicious = sub.add_parser("suspicious")
    p_suspicious.add_argument("--history", action="store_true", help="mostra sinais já resolvidos")
    p_suspicious.add_argument("--since-s", type=int, default=86400)
    p_suspicious.set_defaults(func=cmd_suspicious)

    p_resolve = sub.add_parser("resolve")
    p_resolve.add_argument("id", type=int)
    p_resolve.set_defaults(func=cmd_resolve)

    sub.add_parser("clear-suspicious", help="marca TODOS os sinais abertos como resolvidos de uma vez"
                    ).set_defaults(func=cmd_clear_suspicious)

    p_toggles = sub.add_parser("toggles", help="liga/desliga detectores e a explicação por IA")
    toggles_sub = p_toggles.add_subparsers(dest="toggles_action", required=True)
    toggles_sub.add_parser("list").set_defaults(func=cmd_toggles_list)
    p_toggles_set = toggles_sub.add_parser("set")
    p_toggles_set.add_argument("key", choices=sorted(configio.DEFAULT_FEATURE_TOGGLES))
    p_toggles_set.add_argument("value", choices=["on", "off"])
    p_toggles_set.set_defaults(func=cmd_toggles_set)

    p_whitelist = sub.add_parser("whitelist")
    whitelist_sub = p_whitelist.add_subparsers(dest="whitelist_action", required=True)
    p_wl_add = whitelist_sub.add_parser("add")
    p_wl_add.add_argument("ip")
    p_wl_add.set_defaults(func=cmd_whitelist_add)
    p_wl_del = whitelist_sub.add_parser("del")
    p_wl_del.add_argument("ip")
    p_wl_del.set_defaults(func=cmd_whitelist_del)

    p_customers = sub.add_parser("customers", help="cadastro de redes de clientes (customers.yaml)")
    customers_sub = p_customers.add_subparsers(dest="customers_action", required=True)
    p_cust_add = customers_sub.add_parser("add")
    p_cust_add.add_argument("network", help="CIDR (ou IP único) da rede do cliente, ex.: 177.86.16.0/24")
    p_cust_add.add_argument("prefix", help="rótulo do cliente usado como customer_prefix nos sinais")
    p_cust_add.add_argument("--name", default="")
    p_cust_add.set_defaults(func=cmd_customers_add)
    p_cust_del = customers_sub.add_parser("del")
    p_cust_del.add_argument("network")
    p_cust_del.set_defaults(func=cmd_customers_del)

    p_block = sub.add_parser("block", help="bloqueio manual de IP (FlowSpec via FlowGuard)")
    block_sub = p_block.add_subparsers(dest="block_action", required=True)
    p_block_add = block_sub.add_parser("add")
    p_block_add.add_argument("ip", help="IP ou CIDR a bloquear (origem)")
    p_block_add.add_argument("--ttl-s", type=int, default=None, dest="ttl_s",
                              help="expira em N segundos (padrão: mitigation.default_ttl_s do FlowGuard)")
    p_block_add.set_defaults(func=cmd_block_add)
    p_block_del = block_sub.add_parser("del")
    p_block_del.add_argument("id", type=int)
    p_block_del.set_defaults(func=cmd_block_del)
    block_sub.add_parser("list").set_defaults(func=cmd_block_list)

    p_edge = sub.add_parser("edge", help="mitigação direta na borda (SSH/ACL no roteador, sem depender do FlowGuard)")
    edge_sub = p_edge.add_subparsers(dest="edge_action", required=True)
    p_edge_apply = edge_sub.add_parser("apply")
    p_edge_apply.add_argument("ip", help="IP a bloquear na borda")
    p_edge_apply.add_argument("--ttl-s", type=int, default=None, dest="ttl_s",
                               help="expira em N segundos (padrão: edge_mitigation.yaml default_ttl_s)")
    p_edge_apply.set_defaults(func=cmd_edge_apply)
    p_edge_revert = edge_sub.add_parser("revert")
    p_edge_revert.add_argument("id", type=int)
    p_edge_revert.set_defaults(func=cmd_edge_revert)
    p_edge_list = edge_sub.add_parser("list")
    p_edge_list.add_argument("--active-only", action="store_true", dest="active_only")
    p_edge_list.set_defaults(func=cmd_edge_list)
    p_edge_auto = edge_sub.add_parser("auto", help="gatilho automático por detector")
    edge_auto_sub = p_edge_auto.add_subparsers(dest="edge_auto_action", required=True)
    edge_auto_sub.add_parser("list").set_defaults(func=cmd_edge_auto_list)
    p_edge_auto_set = edge_auto_sub.add_parser("set")
    p_edge_auto_set.add_argument("detector", choices=sorted(edge_mitigation.DEFAULT_CONFIG["auto_mitigate"]))
    p_edge_auto_set.add_argument("value", choices=["on", "off"])
    p_edge_auto_set.set_defaults(func=cmd_edge_auto_set)

    sub.add_parser("reload").set_defaults(func=cmd_reload)
    sub.add_parser("stop").set_defaults(func=cmd_stop)

    args = parser.parse_args()
    sock_path = args.socket or resolve_socket_path(args.config)
    fg_sock_path = resolve_flowguard_socket_path(args.config)

    if args.command is None:
        run_interactive(sock_path, fg_sock_path, args.interval)
        return

    args.func(args, sock_path)


if __name__ == "__main__":
    main()
