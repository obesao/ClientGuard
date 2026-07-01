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


def resolve_socket_path(config_path: str) -> str:
    try:
        with open(config_path, "r", encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh)
        return cfg["daemon"]["socket"]
    except (OSError, KeyError, TypeError):
        return DEFAULT_SOCKET_PATH


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
    for row in resp["suspicious"]:
        table.add_row(
            str(row["id"]), row["src_ip"], row["customer_prefix"] or "-",
            SIGNAL_LABELS.get(row["signal_type"], row["signal_type"]),
            f"{(row['confidence'] or 0) * 100:.0f}%", fmt_ts(row["ts_detected"]), fmt_ts(row["ts_last_seen"]),
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


def cmd_reload(args: argparse.Namespace, sock_path: str) -> None:
    resp = send_command(sock_path, {"cmd": "reload"})
    _print_simple(resp, ok_message="config recarregado (clientes e whitelist)")


def cmd_stop(args: argparse.Namespace, sock_path: str) -> None:
    resp = send_command(sock_path, {"cmd": "stop"})
    _print_simple(resp, ok_message="sinal de parada enviado ao daemon")


# --- modo interativo -------------------------------------------------------

def build_dashboard(sock_path: str) -> Group:
    status = send_command(sock_path, {"cmd": "status"})
    now_str = time.strftime("%Y-%m-%d %H:%M:%S")
    if not status.get("ok"):
        header = Panel(f"[red]Daemon indisponível: {status.get('error')}[/red]", title="ClientGuard Monitor")
        return Group(header)

    top = send_command(sock_path, {"cmd": "top", "limit": 10})
    suspicious = send_command(sock_path, {"cmd": "suspicious"})

    statusbar = (
        f"Flows/janela: [bold]{status['flows_window']}[/bold]  |  "
        f"Clientes ativos: [bold]{status['distinct_src_ips']}[/bold]  |  "
        f"Sinais abertos: [bold red]{status['open_signals']}[/bold red]  |  "
        f"Cadastrados: [bold]{status['n_customers']}[/bold]  |  "
        f"Whitelist: [bold]{status['n_whitelist']}[/bold]  |  Daemon: [green]OK[/green]"
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


def run_interactive(sock_path: str, interval: float) -> None:
    try:
        with Live(build_dashboard(sock_path), console=console, screen=True, auto_refresh=False) as live:
            while True:
                time.sleep(interval)
                live.update(build_dashboard(sock_path), refresh=True)
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

    sub.add_parser("reload").set_defaults(func=cmd_reload)
    sub.add_parser("stop").set_defaults(func=cmd_stop)

    args = parser.parse_args()
    sock_path = args.socket or resolve_socket_path(args.config)

    if args.command is None:
        run_interactive(sock_path, args.interval)
        return

    args.func(args, sock_path)


if __name__ == "__main__":
    main()
