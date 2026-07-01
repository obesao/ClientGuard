#!/usr/bin/env python3
"""ClientGuard — coletor mínimo: captura passiva do mesmo NetFlow que já chega pro
FlowGuard (sem competir pelo socket dele), agrega por src_ip (o cliente, não o
prefixo de destino) e grava em SQLite próprio."""

from __future__ import annotations

import logging
import queue
import sys
import threading
import time
from collections import defaultdict
from pathlib import Path

import yaml
from scapy.all import sniff

sys.path.insert(0, "/root/flowguard")  # reuso somente-leitura do parser do FlowGuard
from collector.netflow import parse_packet, TemplateStore  # noqa: E402

import storage

LOG = logging.getLogger("clientguard")

DEFAULT_CONFIG_PATH = str(Path(__file__).resolve().parent / "config.yaml")


def load_yaml_list(path: str) -> list:
    try:
        return yaml.safe_load(open(path, encoding="utf-8")) or []
    except FileNotFoundError:
        return []


def resolve_customer_prefix(src_ip: str, customers: list[dict]) -> str | None:
    for c in customers:
        if src_ip == c.get("ip"):
            return c.get("prefix")
    return None


class ClientGuardDaemon:
    def __init__(self, config_path: str):
        self.config = yaml.safe_load(open(config_path, encoding="utf-8"))
        self.template_store = TemplateStore()
        self.queue: queue.Queue = queue.Queue(maxsize=200_000)
        self.conn = storage.connect(self.config["database"]["path"], check_same_thread=False)
        self.customers = load_yaml_list(self.config["customer_registry"])
        self._stop = threading.Event()
        self._cycle_count = 0

    def _handle_packet(self, pkt) -> None:
        if not pkt.haslayer("UDP"):
            return
        payload = bytes(pkt["UDP"].payload)
        peer = pkt["IP"].src if pkt.haslayer("IP") else "?"
        try:
            records = parse_packet(payload, peer, self.template_store, self.config["capture"]["sampling_rate"])
        except Exception:
            LOG.exception("erro ao parsear pacote NetFlow de %s", peer)
            return
        for rec in records:
            try:
                self.queue.put_nowait(rec)
            except queue.Full:
                LOG.warning("queue interna cheia, descartando flow")

    def capture_loop(self) -> None:
        cap_cfg = self.config["capture"]
        sniff(
            iface=cap_cfg["iface"], filter=cap_cfg["bpf_filter"], prn=self._handle_packet,
            store=False, stop_filter=lambda _pkt: self._stop.is_set(),
        )

    def aggregate_once(self) -> None:
        records = []
        while True:
            try:
                records.append(self.queue.get_nowait())
            except queue.Empty:
                break

        groups: dict[tuple, dict] = defaultdict(lambda: {"bytes": 0, "packets": 0})
        for rec in records:
            key = (rec.src_ip, rec.dst_ip, rec.dst_port, rec.protocol)
            g = groups[key]
            g["bytes"] += rec.real_bytes
            g["packets"] += rec.real_packets

        now = int(time.time())
        rows = [
            {
                "ts": now, "src_ip": src_ip, "customer_prefix": resolve_customer_prefix(src_ip, self.customers),
                "dst_ip": dst_ip, "dst_port": dst_port, "protocol": protocol,
                "bytes": g["bytes"], "packets": g["packets"],
            }
            for (src_ip, dst_ip, dst_port, protocol), g in groups.items()
        ]
        if rows:
            storage.insert_client_flow_aggs_batch(self.conn, rows)
            LOG.info("agregação: %d flows -> %d grupos (src_ip,dst_ip,dst_port,protocolo)", len(records), len(groups))

        self._cycle_count += 1
        interval = self.config["database"]["aggregate_interval_s"]
        cycles_per_hour = max(1, int(3600 / interval))
        if self._cycle_count % cycles_per_hour == 0:
            pruned = storage.prune_old_aggs(self.conn, self.config["database"]["retention_days"])
            if pruned:
                LOG.info("retenção: %d agregados antigos removidos", pruned)

    def run(self) -> None:
        interval = self.config["database"]["aggregate_interval_s"]
        capture_thread = threading.Thread(target=self.capture_loop, daemon=True, name="clientguard-capture")
        capture_thread.start()
        LOG.info(
            "ClientGuard iniciado — captura passiva em %s (%s)",
            self.config["capture"]["iface"], self.config["capture"]["bpf_filter"],
        )
        try:
            while not self._stop.is_set():
                time.sleep(interval)
                self.aggregate_once()
        except KeyboardInterrupt:
            pass
        finally:
            self._stop.set()
            LOG.info("ClientGuard encerrado")


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s [%(name)s] %(message)s")
    config_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_CONFIG_PATH
    daemon = ClientGuardDaemon(config_path)
    daemon.run()


if __name__ == "__main__":
    main()
