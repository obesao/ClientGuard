"""Testa o parsing/matching do feed de reputação — sem baixar nada da rede."""

from __future__ import annotations

import threat_feed


def test_parse_lines_ignores_comments_and_blank_lines():
    lines = ["# comentário", "", "1.2.3.4", ";outro comentário", "5.6.7.0/24"]
    assert threat_feed._parse_lines(lines) == {"1.2.3.4", "5.6.7.0/24"}


def test_parse_lines_strips_extra_columns():
    # spamhaus DROP: "CIDR ; SBLxxxx" / ipsum: "ip<TAB>contagem"
    lines = ["203.0.113.0/24 ; SBL12345", "198.51.100.1\t42"]
    assert threat_feed._parse_lines(lines) == {"203.0.113.0/24", "198.51.100.1"}


def test_parse_lines_ignores_invalid_entries():
    assert threat_feed._parse_lines(["não-é-um-ip-nem-cidr", "1.2.3.4"]) == {"1.2.3.4"}


def test_threat_feed_matches_single_ip(tmp_path):
    cache = tmp_path / "threat_ips.txt"
    cache.write_text("198.51.100.99\n")
    feed = threat_feed.ThreatFeed(str(cache))
    assert feed.is_malicious("198.51.100.99") is True
    assert feed.is_malicious("8.8.8.8") is False


def test_threat_feed_matches_cidr_block(tmp_path):
    cache = tmp_path / "threat_ips.txt"
    cache.write_text("203.0.113.0/24\n")
    feed = threat_feed.ThreatFeed(str(cache))
    assert feed.is_malicious("203.0.113.55") is True
    assert feed.is_malicious("203.0.114.1") is False


def test_threat_feed_missing_cache_file_matches_nothing(tmp_path):
    feed = threat_feed.ThreatFeed(str(tmp_path / "nao-existe.txt"))
    assert feed.is_malicious("198.51.100.99") is False


def test_threat_feed_invalid_query_ip_returns_false(tmp_path):
    cache = tmp_path / "threat_ips.txt"
    cache.write_text("198.51.100.99\n")
    feed = threat_feed.ThreatFeed(str(cache))
    assert feed.is_malicious("não-é-um-ip") is False
