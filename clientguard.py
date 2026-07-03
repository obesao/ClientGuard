#!/usr/bin/env python3
"""ClientGuard — coletor mínimo: captura passiva do mesmo NetFlow que já chega pro
FlowGuard (sem competir pelo socket dele), agrega pelo cliente (não o prefixo de
destino) e grava em SQLite próprio. O lado "cliente" do flow pode ser src ou dst
dependendo da direção — ver customer_registry.classify_client_side."""

from __future__ import annotations

import logging
import queue
import sys
import threading
import time
from pathlib import Path

import yaml
from scapy.all import sniff

sys.path.insert(0, "/root/flowguard")  # reuso somente-leitura do parser do FlowGuard
from collector.netflow import parse_packet, TemplateStore  # noqa: E402

import ai_client
import configio
import detector
import edge_mitigation
import geoip
import socket_server
import storage
import threat_feed
from customer_registry import WhitelistMatcher, classify_client_side

LOG = logging.getLogger("clientguard")

DEFAULT_CONFIG_PATH = str(Path(__file__).resolve().parent / "config.yaml")


class ClientGuardDaemon:
    def __init__(self, config_path: str):
        self.config = yaml.safe_load(open(config_path, encoding="utf-8"))
        self.template_store = TemplateStore()
        self.queue: queue.Queue = queue.Queue(maxsize=200_000)
        self.conn = storage.connect(self.config["database"]["path"], check_same_thread=False)
        self.db_lock = threading.Lock()
        # contagem incremental (não reconta via COUNT(*) a cada "status" — ver
        # storage.daemon_stats) — só a carga inicial faz uma varredura completa.
        self.total_rows = self.conn.execute("SELECT COUNT(*) FROM client_flow_aggs").fetchone()[0]
        self.customers = configio.load_yaml_list(self.config["customer_registry"])
        self.whitelist = WhitelistMatcher(configio.load_yaml_list(self.config["whitelist_file"]))
        self.toggles = configio.load_feature_toggles(self.config.get("feature_toggles_file", ""))
        self.edge_cfg = edge_mitigation.load_config(
            self.config.get("edge_mitigation_file", edge_mitigation.DEFAULT_CONFIG_PATH))
        self.ai_client = ai_client.AIClient(self.config.get("ai", {}))
        self.threat_feed = threat_feed.ThreatFeed(self.config.get("threat_feed", {}).get("cache_file", ""))
        self.geoip = geoip.GeoIPCache(self.conn, self.db_lock)
        self._stop = threading.Event()
        self._cycle_count = 0
        self.started_at = time.time()
        self.socket_server = socket_server.SocketServer(self)

    def reload_config(self) -> None:
        self.customers = configio.load_yaml_list(self.config["customer_registry"])
        self.whitelist = WhitelistMatcher(configio.load_yaml_list(self.config["whitelist_file"]))
        self.toggles = configio.load_feature_toggles(self.config.get("feature_toggles_file", ""))
        self.edge_cfg = edge_mitigation.load_config(
            self.config.get("edge_mitigation_file", edge_mitigation.DEFAULT_CONFIG_PATH))
        LOG.info("config recarregado: %d clientes cadastrados, %d na whitelist, toggles=%s",
                 len(self.customers), len(self.whitelist), self.toggles)

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
        cap_cfg = self.config["capture"]
        sampling_rate = cap_cfg.get("sampling_rate_by_peer", {}).get(peer, cap_cfg["sampling_rate"])
        try:
            records = parse_packet(payload, peer, self.template_store, sampling_rate)
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

        groups: dict[tuple, dict] = {}
        skipped = 0
        # portas de origem do CLIENTE fora desta lista colapsam pra 0 na chave de
        # agregação (ver storage.bucket_client_port) — nenhum detector além do
        # amplifier olha src_port, e sem isso cada conexão distinta do cliente vira
        # uma porta efêmera única, inflando client_flow_aggs sem ganho de detecção.
        amplifier_ports = set(self.config["detection"]["amplifier_ports"])
        for rec in records:
            classified = classify_client_side(rec.src_ip, rec.dst_ip, self.customers)
            if classified is None:
                skipped += 1  # nenhum dos dois lados é cliente cadastrado — fora do escopo
                continue
            client_ip, other_ip, customer_prefix = classified
            if client_ip == rec.src_ip:
                client_port, other_port = rec.src_port, rec.dst_port
            else:
                client_port, other_port = rec.dst_port, rec.src_port
            client_port = storage.bucket_client_port(client_port, amplifier_ports)
            key = (client_ip, client_port, other_ip, other_port, rec.protocol)
            g = groups.setdefault(key, {"bytes": 0, "packets": 0, "customer_prefix": customer_prefix})
            g["bytes"] += rec.real_bytes
            g["packets"] += rec.real_packets

        other_ips = {key[2] for key in groups}
        self.geoip.enrich(other_ips)

        now = int(time.time())
        rows = [
            {
                "ts": now, "src_ip": client_ip, "customer_prefix": g["customer_prefix"],
                "src_port": client_port, "dst_ip": other_ip, "dst_port": other_port, "protocol": protocol,
                "bytes": g["bytes"], "packets": g["packets"],
                "dst_asn": self.geoip.lookup(other_ip)[0], "dst_country": self.geoip.lookup(other_ip)[1],
            }
            for (client_ip, client_port, other_ip, other_port, protocol), g in groups.items()
        ]
        # gate em `records` (houve captura no ciclo), não em `rows` (houve flow atribuível
        # a cliente) — senão um ciclo onde TODO flow capturado é descartado por não bater
        # com nenhum cliente cadastrado (customers.yaml vazio/corrompido, ou só tráfego de
        # trânsito na janela) vira um apagão silencioso: nem loga o ciclo nem roda detecção,
        # e não há nenhum sinal pro operador perceber que a detecção parou.
        if records:
            with self.db_lock:
                if rows:
                    storage.insert_client_flow_aggs_batch(self.conn, rows)
                    self.total_rows += len(rows)
                LOG.info(
                    "agregação: %d flows -> %d grupos (src_ip,src_port,dst_ip,dst_port,protocolo)%s",
                    len(records), len(groups),
                    f", {skipped} sem cliente identificado" if skipped else "",
                )
            detector.run_all(self.conn, self.config, self.whitelist, customers=self.customers,
                              ai_client=self.ai_client, threat_feed=self.threat_feed, db_lock=self.db_lock,
                              toggles=self.toggles, edge_cfg=self.edge_cfg)

        flowguard_path = self.config.get("flowguard_reuse", {}).get("path", "/root/flowguard")
        expired = edge_mitigation.expire_due(self.conn, self.db_lock, self.edge_cfg, flowguard_path)
        if expired:
            LOG.info("mitigação de borda: %d regra(s) revertida(s) por TTL vencido", expired)

        self._cycle_count += 1
        interval = self.config["database"]["aggregate_interval_s"]
        cycles_per_hour = max(1, int(3600 / interval))
        if self._cycle_count % cycles_per_hour == 0:
            with self.db_lock:
                pruned = storage.prune_old_aggs(self.conn, self.config["database"]["retention_days"])
                self.total_rows -= pruned
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
