#!/usr/bin/env python3
"""Gerador de flows NetFlow v9 sintéticos pra testar os detectores do ClientGuard —
diferente do tools/synth_netflow.py do FlowGuard (que simula ataque CHEGANDO no
cliente), aqui o src_ip é o cliente e o padrão suspeito é OUTBOUND (scan, amplificador
hospedado, spam), o que o ClientGuard existe pra detectar. Envia UDP pra
127.0.0.1:2055, mesma porta que o coletor (rodando como serviço) já captura
passivamente na interface loopback.

Uso:
  synth_client_flows.py scan_horizontal --src 177.86.19.77 --dst-port 22 --hosts 40
  synth_client_flows.py scan_vertical --src 177.86.19.78 --dst 45.20.30.40 --ports 40
  synth_client_flows.py amplifier --src 177.86.19.79 --src-port 53 --dsts 5
  synth_client_flows.py spam --src 177.86.19.80 --dst-port 25 --dsts 25
"""

from __future__ import annotations

import argparse
import socket
import struct
import time

TEMPLATE_ID = 256
SOURCE_ID = 100
TEMPLATE_FIELDS = [
    (8, 4),   # IPV4_SRC_ADDR
    (12, 4),  # IPV4_DST_ADDR
    (7, 2),   # L4_SRC_PORT
    (11, 2),  # L4_DST_PORT
    (4, 1),   # PROTOCOL
    (6, 1),   # TCP_FLAGS
    (1, 4),   # IN_BYTES
    (2, 4),   # IN_PKTS
    (21, 4),  # LAST_SWITCHED
    (22, 4),  # FIRST_SWITCHED
]


def build_template_packet(unix_secs: int) -> bytes:
    body = struct.pack("!HH", TEMPLATE_ID, len(TEMPLATE_FIELDS))
    for ftype, flen in TEMPLATE_FIELDS:
        body += struct.pack("!HH", ftype, flen)
    flowset = struct.pack("!HH", 0, 4 + len(body)) + body
    header = struct.pack("!HHIIII", 9, 1, 0, unix_secs, 1, SOURCE_ID)
    return header + flowset


def build_record(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                  protocol: int, tcp_flags: int, n_bytes: int, n_packets: int) -> bytes:
    return (
        socket.inet_aton(src_ip) + socket.inet_aton(dst_ip)
        + struct.pack("!H", src_port) + struct.pack("!H", dst_port)
        + struct.pack("!B", protocol) + struct.pack("!B", tcp_flags)
        + struct.pack("!I", n_bytes) + struct.pack("!I", n_packets)
        + struct.pack("!I", 5000) + struct.pack("!I", 1000)
    )


def build_data_packet(records: list[bytes], unix_secs: int, seq: int) -> bytes:
    body = b"".join(records)
    flowset = struct.pack("!HH", TEMPLATE_ID, 4 + len(body)) + body
    header = struct.pack("!HHIIII", 9, 1, 0, unix_secs, seq, SOURCE_ID)
    return header + flowset


def send(sock: socket.socket, host: str, port: int, packets: list[bytes]) -> None:
    for pkt in packets:
        sock.sendto(pkt, (host, port))


def send_records(args: argparse.Namespace, records: list[bytes]) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    now = int(time.time())
    send(sock, args.host, args.port, [build_template_packet(now)])
    time.sleep(0.1)
    send(sock, args.host, args.port, [build_data_packet(records, now, 2)])


def cmd_scan_horizontal(args: argparse.Namespace) -> None:
    records = [
        build_record(args.src, f"45.{10 + i % 200}.{i % 255}.{(i * 7) % 255}", 40000 + i, args.dst_port,
                     6, 0x02, 60, 1)
        for i in range(args.hosts)
    ]
    send_records(args, records)
    print(f"scan horizontal: {args.src} -> {args.hosts} destinos distintos na porta {args.dst_port}/tcp")


def cmd_scan_vertical(args: argparse.Namespace) -> None:
    records = [
        build_record(args.src, args.dst, 40000 + i, 1 + i, 6, 0x02, 60, 1)
        for i in range(args.ports)
    ]
    send_records(args, records)
    print(f"scan vertical: {args.src} -> {args.dst} em {args.ports} portas distintas")


def cmd_amplifier(args: argparse.Namespace) -> None:
    records = [
        build_record(args.src, f"198.51.{100 + i}.{10 + i}", args.src_port, 33000 + i,
                     17, 0, args.bytes_per_record, args.packets_per_record)
        for i in range(args.dsts)
    ]
    send_records(args, records)
    print(f"amplificador: {args.src} (porta {args.src_port}/udp) -> {args.dsts} destinos, "
          f"{args.bytes_per_record} bytes cada (x sampling_rate do config.yaml)")


def cmd_spam(args: argparse.Namespace) -> None:
    records = [
        build_record(args.src, f"203.0.{i % 255}.{(i * 3) % 255}", 50000 + i, args.dst_port, 6, 0x18, 400, 3)
        for i in range(args.dsts)
    ]
    send_records(args, records)
    print(f"spam: {args.src} -> {args.dsts} destinos distintos na porta {args.dst_port}/tcp")


def cmd_malicious(args: argparse.Namespace) -> None:
    records = [build_record(args.src, args.dst, 45000, 443, 6, 0x18, 600, 4)]
    send_records(args, records)
    print(f"contato malicioso: {args.src} -> {args.dst} (deve estar no threat_ips.txt)")


def cmd_coordinated(args: argparse.Namespace) -> None:
    srcs = args.srcs.split(",")
    records = [build_record(src.strip(), args.dst, 50000 + i, args.dst_port, 6, 0x18, 300, 3)
               for i, src in enumerate(srcs)]
    send_records(args, records)
    print(f"destino coordenado: {len(srcs)} clientes -> {args.dst}:{args.dst_port}")


def cmd_dns_tunnel(args: argparse.Namespace) -> None:
    total_bytes = args.pkt_size * args.packets
    records = [build_record(args.src, args.dst, 53000, 53, 17, 0, total_bytes, args.packets)]
    send_records(args, records)
    real_packets = args.packets * args.sampling_rate
    print(f"dns tunneling: {args.src} -> {args.dst}:53, {args.packets} pacotes amostrados "
          f"(~{real_packets} reais com sampling_rate={args.sampling_rate})")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=2055)
    sub = parser.add_subparsers(dest="mode", required=True)

    p_sh = sub.add_parser("scan_horizontal", help="1 cliente -> N hosts distintos, mesma porta (reconhecimento)")
    p_sh.add_argument("--src", default="177.86.19.77")
    p_sh.add_argument("--dst-port", type=int, default=22)
    p_sh.add_argument("--hosts", type=int, default=40)
    p_sh.set_defaults(func=cmd_scan_horizontal)

    p_sv = sub.add_parser("scan_vertical", help="1 cliente -> 1 host, N portas distintas (vulnerabilidade)")
    p_sv.add_argument("--src", default="177.86.19.78")
    p_sv.add_argument("--dst", default="45.20.30.40")
    p_sv.add_argument("--ports", type=int, default=40)
    p_sv.set_defaults(func=cmd_scan_vertical)

    p_amp = sub.add_parser("amplifier", help="cliente respondendo em porta UDP conhecida pra vários destinos, volume alto")
    p_amp.add_argument("--src", default="177.86.19.79")
    p_amp.add_argument("--src-port", type=int, default=53, choices=[53, 123, 1900, 11211, 389])
    p_amp.add_argument("--dsts", type=int, default=5)
    p_amp.add_argument("--bytes-per-record", type=int, default=10000,
                        help="multiplicado pelo sampling_rate do config.yaml (default 1000x) ao agregar")
    p_amp.add_argument("--packets-per-record", type=int, default=20)
    p_amp.set_defaults(func=cmd_amplifier)

    p_spam = sub.add_parser("spam", help="cliente com TCP outbound em porta de e-mail pra muitos destinos")
    p_spam.add_argument("--src", default="177.86.19.80")
    p_spam.add_argument("--dst-port", type=int, default=25, choices=[25, 465, 587])
    p_spam.add_argument("--dsts", type=int, default=25)
    p_spam.set_defaults(func=cmd_spam)

    p_mal = sub.add_parser("malicious", help="cliente contatando um dst_ip que deve estar no threat feed")
    p_mal.add_argument("--src", default="177.86.20.55")
    p_mal.add_argument("--dst", required=True, help="IP que deve estar em db/threat_ips.txt")
    p_mal.set_defaults(func=cmd_malicious)

    p_coord = sub.add_parser("coordinated", help="N clientes distintos -> mesmo dst_ip:dst_port (fora de 80/443/53)")
    p_coord.add_argument("--srcs", default="177.86.21.10,177.86.21.11,177.86.21.12,177.86.21.13",
                          help="lista de src_ip separada por vírgula")
    p_coord.add_argument("--dst", default="198.51.44.90")
    p_coord.add_argument("--dst-port", type=int, default=6667)
    p_coord.set_defaults(func=cmd_coordinated)

    p_dns = sub.add_parser("dns_tunnel", help="cliente com volume alto de queries DNS pro mesmo resolver")
    p_dns.add_argument("--src", default="177.86.23.20")
    p_dns.add_argument("--dst", default="203.0.113.53", help="resolver externo")
    p_dns.add_argument("--packets", type=int, default=25, help="pacotes amostrados (pré sampling_rate)")
    p_dns.add_argument("--pkt-size", type=int, default=90, help="bytes por pacote (query DNS típica é pequena)")
    p_dns.add_argument("--sampling-rate", type=int, default=1000, help="só pra exibir a estimativa no print")
    p_dns.set_defaults(func=cmd_dns_tunnel)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
