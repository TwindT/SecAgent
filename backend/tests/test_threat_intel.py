"""
2.8 威胁情报查询工具 — 测试 (pytest)

覆盖 query_otx_ip / query_otx_domain / query_otx_hash /
     query_urlhaus / query_threat_intel 五个入口函数，
    以及 IOC 自动检测和降级处理。
"""

import os
import sys
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from app.tools.threat_intel import (
    query_otx_ip,
    query_otx_domain,
    query_otx_hash,
    query_urlhaus,
    query_threat_intel,
    _detect_ioc_type,
    _degraded_result,
)


# ====================================================================
# _detect_ioc_type
# ====================================================================
class TestDetectIocType:
    def test_detect_ipv4(self):
        assert _detect_ioc_type("192.168.1.1") == "ip"
        assert _detect_ioc_type("8.8.8.8") == "ip"

    def test_detect_md5(self):
        assert _detect_ioc_type("d41d8cd98f00b204e9800998ecf8427e") == "hash"

    def test_detect_sha1(self):
        assert _detect_ioc_type("da39a3ee5e6b4b0d3255bfef95601890afd80709") == "hash"

    def test_detect_sha256(self):
        assert _detect_ioc_type("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == "hash"

    def test_detect_url(self):
        assert _detect_ioc_type("https://evil.example.com/payload") == "url"
        assert _detect_ioc_type("http://malware.site/drop") == "url"

    def test_detect_domain(self):
        assert _detect_ioc_type("evil.example.com") == "domain"
        assert _detect_ioc_type("cdn.bad.org") == "domain"

    def test_detect_unknown(self):
        assert _detect_ioc_type("not_a_valid_ioc") is None
        assert _detect_ioc_type("") is None


# ====================================================================
# _degraded_result
# ====================================================================
class TestDegradedResult:
    def test_structure(self):
        result = _degraded_result("ip", "1.2.3.4", "timeout")
        assert result["status"] == "error"
        assert result["ioc_type"] == "ip"
        assert result["ioc_value"] == "1.2.3.4"
        assert result["malicious"] is None
        assert result["pulse_count"] == 0
        assert "timeout" in result["error"]


# ====================================================================
# query_otx_ip
# ====================================================================
class TestQueryOtxIp:
    @patch("app.tools.threat_intel.httpx.get")
    def test_malicious_ip(self, mock_get):
        """恶意 IP 应返回 malicious=True + pulse 信息。"""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "pulse_info": {
                "count": 5,
                "pulses": [
                    {
                        "id": "p1",
                        "name": "C2 Campaign X",
                        "description": "This IP is a known C2 server.",
                        "created": "2024-01-15",
                        "tags": ["c2", "apt"],
                    }
                ],
            },
            "validation": [],
        }
        mock_resp.raise_for_status.return_value = None
        mock_get.return_value = mock_resp

        result = query_otx_ip("10.0.0.99")
        assert result["status"] == "ok"
        assert result["ioc_type"] == "ip"
        assert result["ioc_value"] == "10.0.0.99"
        assert result["malicious"] is True
        assert result["pulse_count"] == 5
        assert len(result["top_pulses"]) == 1
        assert result["top_pulses"][0]["name"] == "C2 Campaign X"
        assert result["error"] is None

    @patch("app.tools.threat_intel.httpx.get")
    def test_clean_ip(self, mock_get):
        """正常 IP pulse_count=0 应返回 malicious=False。"""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "pulse_info": {"count": 0, "pulses": []},
            "validation": [],
        }
        mock_resp.raise_for_status.return_value = None
        mock_get.return_value = mock_resp

        result = query_otx_ip("8.8.8.8")
        assert result["status"] == "ok"
        assert result["malicious"] is False
        assert result["pulse_count"] == 0

    @patch("app.tools.threat_intel.httpx.get")
    def test_api_http_error(self, mock_get):
        """OTX API HTTP 错误应降级返回。"""
        import httpx
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Forbidden", request=MagicMock(), response=mock_resp
        )
        mock_get.return_value = mock_resp

        result = query_otx_ip("10.0.0.1")
        assert result["status"] == "error"
        assert result["malicious"] is None
        assert "403" in result["error"]

    @patch("app.tools.threat_intel.httpx.get")
    def test_api_network_error(self, mock_get):
        """OTX API 网络错误应降级返回。"""
        import httpx
        mock_get.side_effect = httpx.RequestError("Connection refused")

        result = query_otx_ip("10.0.0.1")
        assert result["status"] == "error"
        assert result["malicious"] is None
        assert "连接失败" in result["error"]


# ====================================================================
# query_otx_domain
# ====================================================================
class TestQueryOtxDomain:
    @patch("app.tools.threat_intel.httpx.get")
    def test_malicious_domain(self, mock_get):
        """恶意域名应返回 malicious=True。"""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "pulse_info": {
                "count": 3,
                "pulses": [
                    {
                        "id": "p2",
                        "name": "Phishing Campaign",
                        "description": "Domain used for phishing.",
                        "created": "2024-03-01",
                        "tags": ["phishing"],
                    }
                ],
            },
            "validation": [],
        }
        mock_resp.raise_for_status.return_value = None
        mock_get.return_value = mock_resp

        result = query_otx_domain("evil.example.com")
        assert result["status"] == "ok"
        assert result["ioc_type"] == "domain"
        assert result["malicious"] is True
        assert result["pulse_count"] == 3

    @patch("app.tools.threat_intel.httpx.get")
    def test_unknown_domain(self, mock_get):
        """未知域名 pulse_count=0 应返回 malicious=False。"""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "pulse_info": {"count": 0, "pulses": []},
            "validation": [],
        }
        mock_resp.raise_for_status.return_value = None
        mock_get.return_value = mock_resp

        result = query_otx_domain("normal-site.com")
        assert result["status"] == "ok"
        assert result["malicious"] is False


# ====================================================================
# query_otx_hash
# ====================================================================
class TestQueryOtxHash:
    @patch("app.tools.threat_intel.httpx.get")
    def test_malicious_hash(self, mock_get):
        """已知恶意 Hash 应返回 malicious=True。"""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "pulse_info": {
                "count": 12,
                "pulses": [
                    {
                        "id": "p3",
                        "name": "Emotet Sample",
                        "description": "This hash belongs to Emotet trojan.",
                        "created": "2024-02-10",
                        "tags": ["emotet", "trojan"],
                    }
                ],
            },
            "validation": [],
        }
        mock_resp.raise_for_status.return_value = None
        mock_get.return_value = mock_resp

        result = query_otx_hash("d41d8cd98f00b204e9800998ecf8427e")
        assert result["status"] == "ok"
        assert result["ioc_type"] == "hash"
        assert result["malicious"] is True
        assert result["pulse_count"] == 12

    @patch("app.tools.threat_intel.httpx.get")
    def test_clean_hash(self, mock_get):
        """未知 Hash 应返回 malicious=False。"""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "pulse_info": {"count": 0, "pulses": []},
            "validation": [],
        }
        mock_resp.raise_for_status.return_value = None
        mock_get.return_value = mock_resp

        result = query_otx_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        assert result["status"] == "ok"
        assert result["malicious"] is False


# ====================================================================
# query_urlhaus
# ====================================================================
class TestQueryUrlhaus:
    @patch("app.tools.threat_intel.httpx.post")
    def test_malicious_url(self, mock_post):
        """URLhaus 收录的恶意 URL 应返回 malicious=True + 标签。"""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "query_status": "ok",
            "url_status": "online",
            "url_id": "12345",
            "host": "evil.example.com",
            "url": "https://evil.example.com/payload",
            "tags": ["emotet", "exe"],
            "threat": "malware_download",
            "urlhaus_reference": "https://urlhaus.abuse.ch/url/12345/",
            "firstseen": "2024-01-01 00:00:00",
        }
        mock_resp.raise_for_status.return_value = None
        mock_post.return_value = mock_resp

        result = query_urlhaus("https://evil.example.com/payload")
        assert result["status"] == "ok"
        assert result["ioc_type"] == "url"
        assert result["malicious"] is True
        assert result["url_status"] == "online"
        assert "emotet" in result["tags"]
        assert result["threat"] == "malware_download"
        assert result["source"] == "URLhaus"
        assert result["error"] is None

    @patch("app.tools.threat_intel.httpx.post")
    def test_clean_url(self, mock_post):
        """未收录的 URL 应返回 malicious=False。"""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "query_status": "no_results",
        }
        mock_resp.raise_for_status.return_value = None
        mock_post.return_value = mock_resp

        result = query_urlhaus("https://safe-site.com/page")
        assert result["status"] == "ok"
        assert result["malicious"] is False
        assert result["url_status"] == "not_found"
        assert result["tags"] == []

    @patch("app.tools.threat_intel.httpx.post")
    def test_api_error(self, mock_post):
        """URLhaus API 错误应降级返回。"""
        import httpx
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Server Error", request=MagicMock(), response=mock_resp
        )
        mock_post.return_value = mock_resp

        result = query_urlhaus("https://test.com/malware")
        assert result["status"] == "error"
        assert result["malicious"] is None
        assert "500" in result["error"]


# ====================================================================
# query_threat_intel — 统一入口
# ====================================================================
class TestQueryThreatIntel:
    @patch("app.tools.threat_intel.query_otx_ip")
    def test_dispatches_ip(self, mock_ip):
        """ioc_type='ip' 应分发到 query_otx_ip。"""
        mock_ip.return_value = {"status": "ok", "ioc_type": "ip", "malicious": False}
        result = query_threat_intel(ioc_type="ip", ioc_value="8.8.8.8")
        mock_ip.assert_called_once_with("8.8.8.8")
        assert result["ioc_type"] == "ip"

    @patch("app.tools.threat_intel.query_otx_domain")
    def test_dispatches_domain(self, mock_domain):
        """ioc_type='domain' 应分发到 query_otx_domain。"""
        mock_domain.return_value = {"status": "ok", "ioc_type": "domain", "malicious": True}
        result = query_threat_intel(ioc_type="domain", ioc_value="evil.com")
        mock_domain.assert_called_once_with("evil.com")
        assert result["malicious"] is True

    @patch("app.tools.threat_intel.query_urlhaus")
    def test_dispatches_url(self, mock_urlhaus):
        """ioc_type='url' 应分发到 query_urlhaus。"""
        mock_urlhaus.return_value = {"status": "ok", "ioc_type": "url", "malicious": True}
        result = query_threat_intel(ioc_type="url", ioc_value="https://bad.com")
        mock_urlhaus.assert_called_once_with("https://bad.com")
        assert result["malicious"] is True

    @patch("app.tools.threat_intel.query_otx_hash")
    def test_dispatches_hash(self, mock_hash):
        """ioc_type='hash' 应分发到 query_otx_hash。"""
        mock_hash.return_value = {"status": "ok", "ioc_type": "file", "malicious": True}
        result = query_threat_intel(ioc_type="hash", ioc_value="d41d8cd98f00b204e9800998ecf8427e")
        mock_hash.assert_called_once_with("d41d8cd98f00b204e9800998ecf8427e")
        assert result["malicious"] is True

    def test_unsupported_type(self):
        """不支持的 IOC 类型应返回错误。"""
        result = query_threat_intel(ioc_type="email", ioc_value="x@y.com")
        assert result["status"] == "error"
        assert "不支持" in result["error"]

    @patch("app.tools.threat_intel.query_otx_ip")
    def test_auto_detect_fallback(self, mock_ip):
        """即使 ioc_type 为空但值可识别，应自动检测。"""
        mock_ip.return_value = {"status": "ok", "ioc_type": "ip", "malicious": False}
        # ioc_type 不存在于 dispatch 表时，触发自动检测
        result = query_threat_intel(ioc_type="unknown", ioc_value="192.168.1.1")
        # unknown 不在 dispatch 中，但自动检测识别为 ip
        mock_ip.assert_called_once_with("192.168.1.1")
        assert result["ioc_type"] == "ip"

    def test_auto_detect_hash_fallback(self):
        """ioc_type 不在表中但 value 是合法 hash，应自动检测并调用 OTX。"""
        with patch("app.tools.threat_intel.query_otx_hash") as mock_hash:
            mock_hash.return_value = {"status": "ok", "ioc_type": "file", "malicious": False}
            result = query_threat_intel(
                ioc_type="unknown", ioc_value="d41d8cd98f00b204e9800998ecf8427e"
            )
            mock_hash.assert_called_once()
            assert result["malicious"] is False


# ====================================================================
# 返回结构验证
# ====================================================================
class TestResultStructure:
    """验证所有函数返回结构的一致性。"""

    REQUIRED_KEYS = ["status", "ioc_type", "ioc_value", "malicious", "error"]

    @patch("app.tools.threat_intel.httpx.get")
    def test_query_otx_ip_has_required_keys(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "pulse_info": {"count": 1, "pulses": []},
            "validation": [],
        }
        mock_resp.raise_for_status.return_value = None
        mock_get.return_value = mock_resp

        result = query_otx_ip("1.1.1.1")
        for key in self.REQUIRED_KEYS:
            assert key in result, f"缺少字段: {key}"

    @patch("app.tools.threat_intel.httpx.get")
    def test_query_otx_domain_has_required_keys(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "pulse_info": {"count": 0, "pulses": []},
            "validation": [],
        }
        mock_resp.raise_for_status.return_value = None
        mock_get.return_value = mock_resp

        result = query_otx_domain("example.com")
        for key in self.REQUIRED_KEYS:
            assert key in result, f"缺少字段: {key}"

    @patch("app.tools.threat_intel.httpx.get")
    def test_query_otx_hash_has_required_keys(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "pulse_info": {"count": 0, "pulses": []},
            "validation": [],
        }
        mock_resp.raise_for_status.return_value = None
        mock_get.return_value = mock_resp

        result = query_otx_hash("d41d8cd98f00b204e9800998ecf8427e")
        for key in self.REQUIRED_KEYS:
            assert key in result, f"缺少字段: {key}"

    @patch("app.tools.threat_intel.httpx.post")
    def test_query_urlhaus_has_required_keys(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"query_status": "no_results"}
        mock_resp.raise_for_status.return_value = None
        mock_post.return_value = mock_resp

        result = query_urlhaus("https://example.com")
        for key in self.REQUIRED_KEYS:
            assert key in result, f"缺少字段: {key}"
