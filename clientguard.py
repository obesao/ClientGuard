#!/usr/bin/env python3
"""ClientGuard — coletor mínimo: captura passiva do mesmo NetFlow que já chega pro
FlowGuard (sem competir pelo socket dele), agrega por src_ip (o cliente, não o
prefixo de destino) e grava em SQLite próprio."""

from __future__ import annotations

import ipaddress
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

import ai_client
import configio
import detector
import geoip
import socket_server
import storage
import threat_feed

LOG = logging.getLogger("clientguard")

DEFAULT_CONFIG_PATH = str(Path(__file__).resolve().parent / "config.yaml")


def resolve_customer_prefix(src_ip: str, customers: list[dict]) -> str | None:
    try:
        addr = ipaddress.ip_address(src_ip)
    except ValueError:
        return None
    for c in customers:
        network = c.get("network")
        if not network:
            continue
        try:
            if addr in ipaddress.ip_network(network, strict=False):
                return c.get("prefix")
        except ValueError:
            continue
    return None


class ClientGuardDaemon:
    def __init__(self, config_path: str):
        self.config = yaml.safe_load(open(config_path, encoding="utf-8"))
        self.template_store = TemplateStore()
        self.queue: queue.Queue = queue.Queue(maxsize=200_000)
        self.conn = storage.connect(self.config["database"]["path"], check_same_thread=False)
        self.db_lock = threading.Lock()
        self.customers = configio.load_yaml_list(self.config["customer_registry"])
        self.whitelist = set(configio.load_yaml_list(self.config["whitelist_file"]))
        self.ai_client = ai_client.AIClient(self.config.get("ai", {}))
        self.threat_feed = threat_feed.ThreatFeed(self.config.get("threat_feed", {}).get("cache_file", ""))
        self.geoip = geoip.GeoIPCache()
        self._stop = threading.Event()
        self._cycle_count = 0
        self.started_at = time.time()
        self.socket_server = socket_server.SocketServer(self)

    def reload_config(self) -> None:
        self.customers = configio.load_yaml_list(self.config["customer_registry"])
        self.whitelist = set(configio.load_yaml_list(self.config["whitelist_file"]))
        LOG.info("config recarregado: %d clientes cadastrados, %d na whitelist",
                 len(self.customers), len(self.whitelist))

    def threat_feed_loop(self) -> None:
        cfg = self.config.get("threat_feed", {})
        if not cfg.get("enabled"):
            return
        interval_s = float(cfg.get("update_interval_h", 6)) * 3600
        cache_file = cfg["cache_file"]
        sources = cfg.get("sources", [])
        while not self._stop.is_set():
            threat_feed.refresh(sources, cache_file)
            self.threat_feed.load()
            if self._stop.wait(interval_s):
                break

    def stop(self) -> None:
        self._stop.set()
        self.socket_server.close()

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
            key = (rec.src_ip, rec.src_port, rec.dst_ip, rec.dst_port, rec.protocol)
            g = groups[key]
            g["bytes"] += rec.real_bytes
            g["packets"] += rec.real_packets

        dst_ips = {key[2] for key in groups}
        self.geoip.enrich(dst_ips)

        now = int(time.time())
        rows = [
            {
                "ts": now, "src_ip": src_ip, "customer_prefix": resolve_customer_prefix(src_ip, self.customers),
                "src_port": src_port, "dst_ip": dst_ip, "dst_port": dst_port, "protocol": protocol,
                "bytes": g["bytes"], "packets": g["packets"],
                "dst_asn": self.geoip.lookup(dst_ip)[0], "dst_country": self.geoip.lookup(dst_ip)[1],
            }
            for (src_ip, src_port, dst_ip, dst_port, protocol), g in groups.items()
        ]
        if rows:
            with self.db_lock:
                storage.insert_client_flow_aggs_batch(self.conn, rows)
                LOG.info(
                    "agregação: %d flows -> %d grupos (src_ip,src_port,dst_ip,dst_port,protocolo)",
                    len(records), len(groups),
                )
            detector.run_all(self.conn, self.config, self.whitelist, self.ai_client, self.threat_feed,
                              self.db_lock)

        self._cycle_count += 1
        interval = self.config["database"]["aggregate_interval_s"]
        cycles_per_hour = max(1, int(3600 / interval))
        if self._cycle_count % cycles_per_hour == 0:
            with self.db_lock:
                pruned = storage.prune_old_aggs(self.conn, self.config["database"]["retention_days"])
            if pruned:
                LOG.info("retenção: %d agregados antigos removidos", pruned)

    def run(self) -> None:
        interval = self.config["database"]["aggregate_interval_s"]
        capture_thread = threading.Thread(target=self.capture_loop, daemon=True, name="clientguard-capture")
        capture_thread.start()
        socket_thread = threading.Thread(
            target=self.socket_server.serve_forever, daemon=True, name="clientguard-socket",
        )
        socket_thread.start()
        threat_thread = threading.Thread(
            target=self.threat_feed_loop, daemon=True, name="clientguard-threatfeed",
        )
        threat_thread.start()
        LOG.info(
            "ClientGuard iniciado — captura passiva em %s (%s), socket de controle em %s",
            self.config["capture"]["iface"], self.config["capture"]["bpf_filter"], self.socket_server.sock_path,
        )
        try:
            while not self._stop.is_set():
                time.sleep(interval)
                self.aggregate_once()
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()
            LOG.info("ClientGuard encerrado")


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s [%(name)s] %(message)s")
    config_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_CONFIG_PATH
    daemon = ClientGuardDaemon(config_path)
    daemon.run()


if __name__ == "__main__":
    main()
