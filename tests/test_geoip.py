"""Testa o cache de GeoIP sem bater na rede de verdade (Team Cymru é mockado)."""

from __future__ import annotations

import geoip
import storage


def test_enrich_populates_cache_and_persists(conn, monkeypatch):
    monkeypatch.setattr(geoip, "_bulk_query", lambda ips, timeout=3.0: {"8.8.8.8": (15169, "US")})
    cache = geoip.GeoIPCache(conn)
    cache.enrich({"8.8.8.8"})
    assert cache.lookup("8.8.8.8") == (15169, "US")
    assert storage.load_geoip_cache(conn) == {"8.8.8.8": (15169, "US")}


def test_enrich_skips_already_cached_ips(conn, monkeypatch):
    calls = []

    def fake_bulk_query(ips, timeout=3.0):
        calls.append(set(ips))
        return {ip: (1, "US") for ip in ips}

    monkeypatch.setattr(geoip, "_bulk_query", fake_bulk_query)
    cache = geoip.GeoIPCache(conn)
    cache.enrich({"8.8.8.8"})
    cache.enrich({"8.8.8.8", "1.1.1.1"})  # 8.8.8.8 já em cache, só 1.1.1.1 deve ser consultado
    assert calls == [{"8.8.8.8"}, {"1.1.1.1"}]


def test_network_failure_is_not_cached_permanently(conn, monkeypatch):
    # None sinaliza falha de rede — diferente de "consulta ok mas IP sem dado"
    monkeypatch.setattr(geoip, "_bulk_query", lambda ips, timeout=3.0: None)
    cache = geoip.GeoIPCache(conn)
    cache.enrich({"8.8.8.8"})
    assert cache.lookup("8.8.8.8") == (None, None)
    assert storage.load_geoip_cache(conn) == {}  # nada persistido, será retentado depois


def test_successful_query_without_data_for_ip_is_cached_as_none(conn, monkeypatch):
    # consulta respondeu, mas esse IP específico não veio na resposta (ex: IP privado)
    monkeypatch.setattr(geoip, "_bulk_query", lambda ips, timeout=3.0: {})
    cache = geoip.GeoIPCache(conn)
    cache.enrich({"10.0.0.1"})
    assert cache.lookup("10.0.0.1") == (None, None)
    assert storage.load_geoip_cache(conn) == {"10.0.0.1": (None, None)}


def test_cache_survives_reload_from_db(conn, monkeypatch):
    monkeypatch.setattr(geoip, "_bulk_query", lambda ips, timeout=3.0: {"8.8.8.8": (15169, "US")})
    geoip.GeoIPCache(conn).enrich({"8.8.8.8"})

    reloaded = geoip.GeoIPCache(conn)  # simula restart do daemon, mesma conexão/banco
    assert reloaded.lookup("8.8.8.8") == (15169, "US")


def test_lookup_unknown_ip_returns_none_tuple(conn):
    cache = geoip.GeoIPCache(conn)
    assert cache.lookup("9.9.9.9") == (None, None)


def test_works_without_db_persistence(monkeypatch):
    # uso standalone (sem conn) ainda deve funcionar, só sem sobreviver a restart
    monkeypatch.setattr(geoip, "_bulk_query", lambda ips, timeout=3.0: {"8.8.8.8": (15169, "US")})
    cache = geoip.GeoIPCache()
    cache.enrich({"8.8.8.8"})
    assert cache.lookup("8.8.8.8") == (15169, "US")
