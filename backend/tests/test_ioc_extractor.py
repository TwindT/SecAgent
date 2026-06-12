"""
3.4 IOC 提取工具 — 测试 (pytest)

覆盖 extract_iocs 入口函数以及各类型 IOC 的提取、去重和边界情况。
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from app.tools.ioc_extractor import extract_iocs


# ====================================================================
# IPv4 提取
# ====================================================================
class TestExtractIPv4:
    def test_single_ip(self):
        result = extract_iocs("Connection from 192.168.1.100 detected")
        assert result["status"] == "ok"
        assert "192.168.1.100" in result["iocs"]["ipv4"]

    def test_multiple_ips(self):
        result = extract_iocs("Traffic: 10.0.0.1 → 172.16.5.20 → 8.8.8.8")
        assert result["status"] == "ok"
        assert set(result["iocs"]["ipv4"]) == {"10.0.0.1", "172.16.5.20", "8.8.8.8"}

    def test_excludes_reserved_ips(self):
        result = extract_iocs("localhost 127.0.0.1 and broadcast 255.255.255.255 and 0.0.0.0")
        assert "127.0.0.1" not in result["iocs"]["ipv4"]
        assert "255.255.255.255" not in result["iocs"]["ipv4"]
        assert "0.0.0.0" not in result["iocs"]["ipv4"]

    def test_invalid_ip_not_extracted(self):
        """999.999.999.999 不是合法 IPv4，不应被提取。"""
        result = extract_iocs("bogus ip 999.999.999.999 in log")
        assert "999.999.999.999" not in result["iocs"]["ipv4"]


# ====================================================================
# URL 提取
# ====================================================================
class TestExtractURLs:
    def test_http_url(self):
        result = extract_iocs("downloaded from http://malware.example.com/payload.exe")
        assert result["status"] == "ok"
        assert "http://malware.example.com/payload.exe" in result["iocs"]["urls"]

    def test_https_url(self):
        result = extract_iocs("C2 server at https://evil.org/beacon?id=abc")
        assert "https://evil.org/beacon?id=abc" in result["iocs"]["urls"]

    def test_multiple_urls(self):
        result = extract_iocs("urls: https://a.com/bad and http://b.org/drop")
        assert len(result["iocs"]["urls"]) == 2

    def test_no_urls(self):
        result = extract_iocs("no urls here, just plain text")
        assert result["iocs"]["urls"] == []


# ====================================================================
# 域名提取
# ====================================================================
class TestExtractDomains:
    def test_domain(self):
        result = extract_iocs("connected to evil.example.com")
        assert result["status"] == "ok"
        assert "evil.example.com" in result["iocs"]["domains"]

    def test_domain_not_duplicated_with_url(self):
        """已出现在 URL 中的域名不应再被单独列为域名。"""
        result = extract_iocs("got payload from https://malware.site/bad.exe")
        # URL 中已包含 malware.site，域名列表不应重复
        assert "malware.site" not in result["iocs"]["domains"]

    def test_domain_outside_url(self):
        """不在 URL 中的域名应该被单独提取。"""
        result = extract_iocs("c2 server at evil.org and https://some.url/path")
        # evil.org 不在任何 URL 中，应该被提取
        assert "evil.org" in result["iocs"]["domains"]


# ====================================================================
# Hash 提取
# ====================================================================
class TestExtractHashes:
    def test_md5(self):
        result = extract_iocs("file hash d41d8cd98f00b204e9800998ecf8427e is clean")
        assert result["status"] == "ok"
        assert "d41d8cd98f00b204e9800998ecf8427e" in result["iocs"]["hashes"]["md5"]

    def test_sha1(self):
        result = extract_iocs("sha1: da39a3ee5e6b4b0d3255bfef95601890afd80709")
        assert "da39a3ee5e6b4b0d3255bfef95601890afd80709" in result["iocs"]["hashes"]["sha1"]

    def test_sha256(self):
        h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        result = extract_iocs(f"sha256: {h}")
        assert h in result["iocs"]["hashes"]["sha256"]

    def test_sha256_not_also_matched_as_md5_or_sha1(self):
        """SHA256 不应被同时识别为 SHA1 或 MD5。"""
        h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        result = extract_iocs(f"hash={h}")
        assert h not in result["iocs"]["hashes"]["md5"]
        assert h not in result["iocs"]["hashes"]["sha1"]

    def test_multiple_hash_types(self):
        text = "md5=aaaabbbbccccddddeeeeffff00001111 sha256=abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        result = extract_iocs(text)
        assert len(result["iocs"]["hashes"]["md5"]) == 1
        assert len(result["iocs"]["hashes"]["sha256"]) == 1


# ====================================================================
# 混合提取 + 去重
# ====================================================================
class TestMixedExtraction:
    def test_all_types_together(self):
        text = (
            "Report: IP 10.20.30.40 contacted https://evil.com/c2\n"
            "Downloaded file md5=abc123def456abc123def456abc123de\n"
            "Additional domain bad.org also observed\n"
        )
        result = extract_iocs(text)
        assert result["status"] == "ok"
        assert "10.20.30.40" in result["iocs"]["ipv4"]
        assert "https://evil.com/c2" in result["iocs"]["urls"]
        assert "abc123def456abc123def456abc123de" in result["iocs"]["hashes"]["md5"]
        assert "bad.org" in result["iocs"]["domains"]

    def test_total_count(self):
        text = "IPs: 1.1.1.1, 2.2.2.2 | urls: https://a.com, https://b.com | md5=abc123def456abc123def456abc123de"
        result = extract_iocs(text)
        # 2 IP + 2 URL + 1 MD5 = 5 total
        assert result["total"] == 5

    def test_deduplication(self):
        """重复的 IOC 应该被去重。"""
        text = "IP 1.2.3.4 and again 1.2.3.4 and IP 1.2.3.4"
        result = extract_iocs(text)
        assert result["iocs"]["ipv4"] == ["1.2.3.4"]
        assert result["total"] == 1


# ====================================================================
# 边界情况
# ====================================================================
class TestEdgeCases:
    def test_empty_string(self):
        result = extract_iocs("")
        assert result["status"] == "error"
        assert "空" in result["error"]

    def test_none_input(self):
        result = extract_iocs(None)
        assert result["status"] == "error"

    def test_non_string_input(self):
        result = extract_iocs(12345)
        assert result["status"] == "error"

    def test_no_iocs(self):
        result = extract_iocs("This is a normal sentence with no indicators.")
        assert result["status"] == "ok"
        assert result["total"] == 0

    def test_result_structure(self):
        result = extract_iocs("ip 1.2.3.4")
        assert result["status"] == "ok"
        assert "iocs" in result
        assert "total" in result
        assert result["error"] is None
        assert isinstance(result["iocs"]["ipv4"], list)
        assert isinstance(result["iocs"]["domains"], list)
        assert isinstance(result["iocs"]["urls"], list)
        assert isinstance(result["iocs"]["hashes"], dict)
