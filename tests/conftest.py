"""Fixtures compartilhadas — banco em memória com o schema real, sem precisar de
tráfego de rede/captura pra testar a lógica dos detectores isoladamente."""

from __future__ import annotations

import time

import pytest

import storage


@pytest.fixture
def conn():
    c = storage.connect(":memory:", check_same_thread=False)
    yield c
    c.close()


def insert_flow(conn, src_ip, dst_ip, dst_port, protocol, bytes_=100, packets_=1,
                 src_port=0, customer_prefix=None, ts=None):
    # os detectores filtram por "ts >= int(time.time()) - window_s" usando o relógio
    # real — por isso o default aqui é "agora", não um timestamp fixo/congelado.
    storage.insert_client_flow_aggs_batch(conn, [{
        "ts": ts if ts is not None else int(time.time()), "src_ip": src_ip,
        "customer_prefix": customer_prefix, "src_port": src_port,
        "dst_ip": dst_ip, "dst_port": dst_port, "protocol": protocol,
        "bytes": bytes_, "packets": packets_,
    }])
