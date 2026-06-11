"""
2.6 静态分析工具集成 — 测试 (pytest)

覆盖 run_semgrep / run_bandit / scan_code 三个入口函数。
"""

import json
import os
import sys
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from app.tools.scanner import (
    run_semgrep,
    run_bandit,
    scan_code,
    _normalize_findings,
)


# ── 测试样本 ──────────────────────────────────────────────────────────

SQL_INJECTION_CODE = """
import sqlite3

def get_user(username):
    conn = sqlite3.connect('users.db')
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor = conn.execute(query)
    return cursor.fetchall()
"""

SAFE_CODE = """
def add_numbers(a, b):
    return a + b

def greet(name):
    return f"Hello, {name}!"
"""

COMMAND_INJECTION_CODE = """
import os

def run_backup(filename):
    os.system(f"tar -czf backup.tar.gz {filename}")
"""


# ====================================================================
# run_semgrep
# ====================================================================
class TestRunSemgrep:
    def test_detects_sql_injection(self):
        """semgrep 应检出 Python 代码中的 SQL 注入。"""
        result = run_semgrep(SQL_INJECTION_CODE, language="python")

        assert result["status"] == "ok"
        assert result["total"] >= 1
        # 至少有一个 finding 包含 "sql" 关键字
        sql_findings = [
            f for f in result["findings"]
            if "sql" in f["rule_id"].lower() or "sql" in f["message"].lower()
        ]
        assert len(sql_findings) >= 1, f"未检出 SQL 注入: {result['findings']}"

    def test_safe_code_has_fewer_findings(self):
        """安全代码应比漏洞代码产生更少的 findings。"""
        vuln_result = run_semgrep(SQL_INJECTION_CODE, language="python")
        safe_result = run_semgrep(SAFE_CODE, language="python")

        # 安全代码 findings 应该不多于漏洞代码
        assert safe_result["total"] <= vuln_result["total"]

    def test_javascript_detects_xss(self):
        """semgrep 应检出 JS 代码中的 XSS。"""
        js_code = """
const express = require('express');
app.get('/user', (req, res) => {
    res.send('<div>' + req.query.name + '</div>');
});
"""
        result = run_semgrep(js_code, language="javascript")
        assert result["status"] == "ok"
        # 可能有 xss 或 raw-html 相关的 findings
        xss_findings = [
            f for f in result["findings"]
            if "xss" in f["rule_id"].lower() or "xss" in f["message"].lower()
        ]
        assert len(xss_findings) >= 1 or result["total"] >= 1, \
            f"JS 代码未检出任何问题: {result['findings']}"

    def test_result_structure(self):
        """返回结果应包含标准化字段。"""
        result = run_semgrep(SQL_INJECTION_CODE, language="python")
        assert "status" in result
        assert "findings" in result
        assert "total" in result
        assert "error" in result

        for f in result["findings"]:
            assert "rule_id" in f
            assert "severity" in f
            assert "file" in f
            assert "line" in f
            assert "message" in f
            assert "code_snippet" in f
            assert "source" in f
            assert f["source"] == "semgrep"
            # 严重度应为归一化后的值
            assert f["severity"] in ("HIGH", "MEDIUM", "LOW", "INFO")


# ====================================================================
# run_bandit
# ====================================================================
class TestRunBandit:
    def test_detects_sql_injection(self):
        """bandit 应检出 SQL 注入（B608）。"""
        result = run_bandit(SQL_INJECTION_CODE)

        assert result["status"] == "ok"
        b608 = [f for f in result["findings"] if "B608" in f["rule_id"]]
        assert len(b608) >= 1, f"bandit 未检出 SQL 注入 (B608): {result['findings']}"

    def test_detects_command_injection(self):
        """bandit 应检出 os.system 命令注入（B605）。"""
        result = run_bandit(COMMAND_INJECTION_CODE)

        assert result["status"] == "ok"
        b605 = [f for f in result["findings"] if "B605" in f["rule_id"]]
        assert len(b605) >= 1, f"bandit 未检出命令注入 (B605): {result['findings']}"

    def test_safe_code_no_high_severity(self):
        """安全代码不应有 HIGH 严重度 finding。"""
        result = run_bandit(SAFE_CODE)
        high_findings = [f for f in result["findings"] if f["severity"] == "HIGH"]
        assert len(high_findings) == 0, f"安全代码不应有 HIGH 级别发现: {high_findings}"

    def test_result_structure(self):
        """返回结果应包含标准化字段。"""
        result = run_bandit(SQL_INJECTION_CODE)
        assert "status" in result
        assert "findings" in result
        assert "total" in result
        assert "error" in result

        for f in result["findings"]:
            assert "rule_id" in f
            assert "severity" in f
            assert "file" in f
            assert "line" in f
            assert "message" in f
            assert "code_snippet" in f
            assert "source" in f
            assert f["source"] == "bandit"
            assert f["severity"] in ("HIGH", "MEDIUM", "LOW", "INFO")


# ====================================================================
# scan_code — 统一入口
# ====================================================================
class TestScanCode:
    def test_python_uses_both_scanners(self):
        """Python 代码应同时使用 semgrep + bandit。"""
        result = scan_code(SQL_INJECTION_CODE, language="python")

        assert result["status"] == "ok"
        assert "semgrep" in result["scanners"]
        assert "bandit" in result["scanners"]
        assert result["total"] >= 1

    def test_javascript_uses_semgrep_only(self):
        """JavaScript 代码应仅使用 semgrep。"""
        js_code = """
app.get('/user', (req, res) => {
    res.send('<div>' + req.query.name + '</div>');
});
"""
        result = scan_code(js_code, language="javascript")

        assert result["status"] == "ok"
        assert result["scanners"] == ["semgrep"]

    def test_no_duplicate_findings(self):
        """Python 代码 semgrep+bandit 合并后应去重。"""
        result = scan_code(SQL_INJECTION_CODE, language="python")

        # 检查无重复 (rule_id, line)
        seen = set()
        for f in result["findings"]:
            key = (f["rule_id"], f["line"])
            assert key not in seen, f"发现重复 finding: {key}"
            seen.add(key)

    def test_sorted_by_severity(self):
        """findings 应按严重度排序。"""
        result = scan_code(COMMAND_INJECTION_CODE, language="python")

        severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
        prev = 0
        for f in result["findings"]:
            cur = severity_order.get(f["severity"], 99)
            assert cur >= prev, \
                f"排序错误: {f['severity']} 出现在更高严重度之前"
            prev = cur

    def test_result_structure(self):
        """返回结果应包含完整字段。"""
        result = scan_code(SQL_INJECTION_CODE, language="python")
        assert "status" in result
        assert "findings" in result
        assert "total" in result
        assert "scanners" in result
        assert "error" in result


# ====================================================================
# _normalize_findings
# ====================================================================
class TestNormalizeFindings:
    def test_severity_mapping_semgrep(self):
        """semgrep 严重度应正确映射。"""
        raw = [
            {"rule_id": "r1", "severity": "ERROR", "file": "/tmp/a.py", "line": 1,
             "message": "m", "code_snippet": "c"},
            {"rule_id": "r2", "severity": "WARNING", "file": "/tmp/a.py", "line": 2,
             "message": "m", "code_snippet": "c"},
            {"rule_id": "r3", "severity": "INFO", "file": "/tmp/a.py", "line": 3,
             "message": "m", "code_snippet": "c"},
        ]
        result = _normalize_findings(raw, source="test")
        assert result[0]["severity"] == "HIGH"
        assert result[1]["severity"] == "MEDIUM"
        assert result[2]["severity"] == "LOW"

    def test_severity_mapping_bandit(self):
        """bandit 严重度应保持原值。"""
        raw = [
            {"rule_id": "r1", "severity": "HIGH", "file": "/tmp/a.py", "line": 1,
             "message": "m", "code_snippet": "c"},
            {"rule_id": "r2", "severity": "MEDIUM", "file": "/tmp/a.py", "line": 2,
             "message": "m", "code_snippet": "c"},
        ]
        result = _normalize_findings(raw, source="test")
        assert result[0]["severity"] == "HIGH"
        assert result[1]["severity"] == "MEDIUM"

    def test_deduplication(self):
        """相同 (rule_id, line) 应去重。"""
        raw = [
            {"rule_id": "r1", "severity": "HIGH", "file": "/tmp/a.py", "line": 1,
             "message": "m", "code_snippet": "c"},
            {"rule_id": "r1", "severity": "HIGH", "file": "/tmp/b.py", "line": 1,
             "message": "m", "code_snippet": "c"},
        ]
        result = _normalize_findings(raw, source="test")
        assert len(result) == 1

    def test_file_path_basename_only(self):
        """文件路径应仅保留文件名。"""
        raw = [
            {"rule_id": "r1", "severity": "HIGH", "file": "/tmp/subdir/test.py", "line": 1,
             "message": "m", "code_snippet": "c"},
        ]
        result = _normalize_findings(raw, source="test")
        assert result[0]["file"] == "test.py"

    def test_source_field(self):
        """source 字段应正确注入。"""
        raw = [
            {"rule_id": "r1", "severity": "HIGH", "file": "/tmp/a.py", "line": 1,
             "message": "m", "code_snippet": "c"},
        ]
        result = _normalize_findings(raw, source="semgrep")
        assert result[0]["source"] == "semgrep"


# ====================================================================
# 错误处理
# ====================================================================
class TestErrorHandling:
    @patch("subprocess.run")
    def test_run_semgrep_timeout(self, mock_run):
        """semgrep 超时应返回错误格式。"""
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="semgrep", timeout=60)

        result = run_semgrep("code", language="python")
        assert result["status"] == "error"
        assert "超时" in result["error"]

    @patch("subprocess.run")
    def test_run_bandit_timeout(self, mock_run):
        """bandit 超时应返回错误格式。"""
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="bandit", timeout=60)

        result = run_bandit("code")
        assert result["status"] == "error"
        assert "超时" in result["error"]
