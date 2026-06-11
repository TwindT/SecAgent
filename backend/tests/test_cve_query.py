"""
2.7 漏洞库查询工具 — 测试 (pytest)

覆盖 query_cve_by_id / query_cve_by_keyword / query_cwe / query_cve。
"""

import os
import sys
from unittest.mock import patch, MagicMock

import pytest
import httpx

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from app.tools.cve_query import (
    query_cve_by_id,
    query_cve_by_keyword,
    query_cwe,
    query_cve,
    _parse_nvd_cve_item,
)


# ── 测试数据 ──────────────────────────────────────────────────────────

LOG4SHELL_RESPONSE = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-44228",
                "descriptions": [
                    {"lang": "en", "value": "Apache Log4j2 JNDI features..."}
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                "baseScore": 10.0,
                                "baseSeverity": "CRITICAL",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                            }
                        }
                    ]
                },
                "weaknesses": [
                    {"description": [{"lang": "en", "value": "CWE-20"}, {"lang": "en", "value": "CWE-502"}]}
                ],
                "published": "2021-12-10T19:15:00.000",
            }
        }
    ]
}

EMPTY_RESPONSE = {"vulnerabilities": []}


# ── query_cve_by_id ───────────────────────────────────────────────────

class TestQueryCveById:
    @patch("app.tools.cve_query.httpx.get")
    def test_returns_log4shell(self, mock_get):
        """查询 CVE-2021-44228 应返回 Log4Shell 详情。"""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = LOG4SHELL_RESPONSE
        mock_resp.raise_for_status.return_value = None
        mock_get.return_value = mock_resp

        result = query_cve_by_id("CVE-2021-44228")

        assert result["status"] == "ok"
        assert result["data"]["id"] == "CVE-2021-44228"
        assert "Log4j" in result["data"]["description"]
        assert result["data"]["cvss"]["baseScore"] == 10.0
        assert result["data"]["cvss"]["baseSeverity"] == "CRITICAL"
        assert "CWE-20" in result["data"]["cwe_ids"]

    @patch("app.tools.cve_query.httpx.get")
    def test_not_found(self, mock_get):
        """不存在的 CVE 返回 not_found。"""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = EMPTY_RESPONSE
        mock_resp.raise_for_status.return_value = None
        mock_get.return_value = mock_resp

        result = query_cve_by_id("CVE-9999-99999")
        assert result["status"] == "not_found"

    @patch("app.tools.cve_query.httpx.get")
    def test_api_error(self, mock_get):
        """API 错误应正确处理。"""
        mock_resp = MagicMock()
        mock_resp.status_code = 503
        mock_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Server Error", request=MagicMock(), response=mock_resp
        )
        mock_get.return_value = mock_resp

        result = query_cve_by_id("CVE-2021-44228")
        assert result["status"] == "error"
        assert "503" in result["error"]


# ── query_cve_by_keyword ──────────────────────────────────────────────

class TestQueryCveByKeyword:
    @patch("app.tools.cve_query.httpx.get")
    def test_returns_results(self, mock_get):
        """关键字搜索应返回匹配结果。"""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = LOG4SHELL_RESPONSE
        mock_resp.raise_for_status.return_value = None
        mock_get.return_value = mock_resp

        result = query_cve_by_keyword("Log4j", limit=5)

        assert result["status"] == "ok"
        assert result["total"] >= 1
        assert result["data"][0]["id"] == "CVE-2021-44228"

    @patch("app.tools.cve_query.httpx.get")
    def test_limit_respected(self, mock_get):
        """limit 参数应限制返回数量。"""
        many_items = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": f"CVE-2021-{i:05d}",
                        "descriptions": [{"lang": "en", "value": "test"}],
                        "metrics": {},
                        "weaknesses": [],
                        "published": "2021-01-01T00:00:00.000",
                    }
                }
                for i in range(10)
            ]
        }
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = many_items
        mock_resp.raise_for_status.return_value = None
        mock_get.return_value = mock_resp

        result = query_cve_by_keyword("test", limit=3)
        assert result["total"] <= 3


# ── query_cwe ─────────────────────────────────────────────────────────

class TestQueryCwe:
    def test_returns_sql_injection(self):
        """查询 CWE-89 应返回 SQL 注入详情。"""
        result = query_cwe("CWE-89")

        assert result["status"] == "ok"
        assert result["data"]["id"] == "CWE-89"
        assert "SQL" in result["data"]["name"].upper()
        assert "mitigation" in result["data"]
        assert len(result["data"]["mitigation"]) > 10

    def test_case_insensitive(self):
        """CWE ID 大小写不敏感。"""
        result = query_cwe("cwe-79")
        assert result["status"] == "ok"
        assert result["data"]["id"] == "CWE-79"

    def test_not_found(self):
        """不存在的 CWE 返回 not_found。"""
        result = query_cwe("CWE-99999")
        assert result["status"] == "not_found"


# ── query_cve ─────────────────────────────────────────────────────────

class TestQueryCve:
    @patch("app.tools.cve_query.httpx.get")
    def test_dispatches_to_by_id(self, mock_get):
        """提供 cve_id 时应调用 query_cve_by_id。"""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = LOG4SHELL_RESPONSE
        mock_resp.raise_for_status.return_value = None
        mock_get.return_value = mock_resp

        result = query_cve(cve_id="CVE-2021-44228")
        assert result["status"] == "ok"
        assert result["data"]["id"] == "CVE-2021-44228"

    @patch("app.tools.cve_query.httpx.get")
    def test_dispatches_to_keyword(self, mock_get):
        """提供 keyword 时应调用 query_cve_by_keyword。"""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = LOG4SHELL_RESPONSE
        mock_resp.raise_for_status.return_value = None
        mock_get.return_value = mock_resp

        result = query_cve(keyword="Log4j")
        assert result["status"] == "ok"

    def test_no_params_returns_error(self):
        """无参数时返回错误。"""
        result = query_cve()
        assert result["status"] == "error"
        assert "cve_id" in result["error"] or "keyword" in result["error"]


# ── _parse_nvd_cve_item ──────────────────────────────────────────────

class TestParseNvdCveItem:
    def test_parses_log4shell(self):
        """应正确解析 Log4Shell 数据。"""
        item = LOG4SHELL_RESPONSE["vulnerabilities"][0]
        result = _parse_nvd_cve_item(item)

        assert result["id"] == "CVE-2021-44228"
        assert "Apache" in result["description"]
        assert result["cvss"]["baseScore"] == 10.0
        assert result["cvss"]["baseSeverity"] == "CRITICAL"
        assert "CWE-20" in result["cwe_ids"]
        assert result["published"] == "2021-12-10"
