"""
3.5 YARA 规则扫描工具 — 测试 (pytest)

覆盖 YARA 规则编译、scan_yara 入口函数、规则匹配和边界情况。
"""

import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import app.tools.yara_scanner as yara_mod
from app.tools.yara_scanner import scan_yara, _get_rules


# ====================================================================
# 规则编译验证（dev-plan 3.5 核心验收标准）
# ====================================================================
class TestYaraRuleCompilation:
    def test_rules_compile_successfully(self):
        """所有 YARA 规则应成功编译（不抛 SyntaxError）。"""
        rules = _get_rules()
        assert rules is not None, "YARA 规则编译失败"

    def test_at_least_10_rules(self):
        """规则文件数应 ≥ 4（对应 10+ 条规则）。dev-plan 要求。"""
        rules = _get_rules()
        assert rules is not None
        assert yara_mod._compiled_rule_count >= 4, f"预期 ≥ 4 个 .yar 文件，实际 {yara_mod._compiled_rule_count}"

    def test_all_rule_files_present(self):
        """确认 4 个规则文件全部存在。"""
        from pathlib import Path
        rules_dir = Path(__file__).resolve().parent.parent / "data" / "yara_rules"
        yar_files = list(rules_dir.glob("*.yar"))
        names = {f.name for f in yar_files}
        expected = {
            "malware_generic.yar",
            "webshell_detect.yar",
            "trojan_backdoor.yar",
            "anti_analysis.yar",
        }
        assert names == expected, f"规则文件不匹配: {names}"


# ====================================================================
# scan_yara — 规则匹配
# ====================================================================
class TestScanYaraMatching:
    def test_ransomware_match(self):
        """含勒索软件关键词的文本应命中 Ransomware_Indicators。"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("encrypt all files and demand bitcoin ransom BTC")
            path = f.name
        try:
            result = scan_yara(path)
            assert result["status"] == "ok"
            assert result["matched"] is True
            rule_names = [m["rule_name"] for m in result["matches"]]
            assert "Ransomware_Indicators" in rule_names
        finally:
            os.unlink(path)

    def test_credential_theft_match(self):
        """含凭证窃取关键词的文本应命中 Credential_Theft_Indicators。"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("mimikatz lsass sam dump pwdump sekurlsa")
            path = f.name
        try:
            result = scan_yara(path)
            assert result["status"] == "ok"
            assert result["matched"] is True
            rule_names = [m["rule_name"] for m in result["matches"]]
            assert "Credential_Theft_Indicators" in rule_names
        finally:
            os.unlink(path)

    def test_webshell_php_match(self):
        """含 PHP webshell 函数的文本应命中 PHP_Webshell_Backdoor。"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("<?php eval(base64_decode(system('id'))); assert($x); ?>")
            path = f.name
        try:
            result = scan_yara(path)
            assert result["status"] == "ok"
            assert result["matched"] is True
            rule_names = [m["rule_name"] for m in result["matches"]]
            assert "PHP_Webshell_Backdoor" in rule_names
        finally:
            os.unlink(path)

    def test_keylogger_match(self):
        """含键盘记录 API 的文本应命中 Keylogger_Indicators。"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("SetWindowsHookEx GetAsyncKeyState GetForegroundWindow keylog CLIPBOARD")
            path = f.name
        try:
            result = scan_yara(path)
            assert result["status"] == "ok"
            assert result["matched"] is True
            rule_names = [m["rule_name"] for m in result["matches"]]
            assert "Keylogger_Indicators" in rule_names
        finally:
            os.unlink(path)

    def test_anti_debug_match(self):
        """含反调试 API 的文本应命中 Anti_Debug_Techniques。"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("IsDebuggerPresent CheckRemoteDebuggerPresent")
            path = f.name
        try:
            result = scan_yara(path)
            assert result["status"] == "ok"
            assert result["matched"] is True
            rule_names = [m["rule_name"] for m in result["matches"]]
            assert "Anti_Debug_Techniques" in rule_names
        finally:
            os.unlink(path)

    def test_clean_file_no_match(self):
        """普通文本不应命中任何规则。"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("This is a normal document with no suspicious content at all.")
            path = f.name
        try:
            result = scan_yara(path)
            assert result["status"] == "ok"
            assert result["matched"] is False
            assert result["matches"] == []
        finally:
            os.unlink(path)


# ====================================================================
# scan_yara — 返回结构
# ====================================================================
class TestScanYaraStructure:
    def test_match_structure(self):
        """匹配结果应包含所有必要字段。"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("mimikatz lsass sam dump")
            path = f.name
        try:
            result = scan_yara(path)
            assert result["status"] == "ok"
            assert "matched" in result
            assert "matches" in result
            assert "rules_loaded" in result
            assert result["error"] is None
            for m in result["matches"]:
                assert "rule_name" in m
                assert "category" in m
                assert "severity" in m
                assert "description" in m
                assert "matched_strings" in m
        finally:
            os.unlink(path)

    def test_rules_loaded_is_int(self):
        """rules_loaded 应为正整数。"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("test")
            path = f.name
        try:
            result = scan_yara(path)
            assert isinstance(result["rules_loaded"], int)
            assert result["rules_loaded"] >= 4
        finally:
            os.unlink(path)


# ====================================================================
# 边界情况
# ====================================================================
class TestScanYaraEdgeCases:
    def test_file_not_found(self):
        result = scan_yara("/nonexistent/path/to/file.bin")
        assert result["status"] == "error"
        assert "不存在" in result["error"]

    def test_directory_not_file(self):
        result = scan_yara(os.path.dirname(__file__))
        assert result["status"] == "error"
        assert "不是文件" in result["error"]

    def test_empty_path(self):
        result = scan_yara("")
        assert result["status"] == "error"

    def test_none_path(self):
        result = scan_yara(None)
        assert result["status"] == "error"

    def test_non_string_path(self):
        result = scan_yara(12345)
        assert result["status"] == "error"


# ====================================================================
# extract_file_features 集成
# ====================================================================
class TestYaraIntegrationWithExtractFileFeatures:
    def test_yara_scan_field_present(self):
        """extract_file_features 返回应包含 yara_scan 字段。"""
        from app.tools.file_analysis import extract_file_features

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("mimikatz lsass credential dump")
            path = f.name
        try:
            result = extract_file_features(path)
            assert result["status"] == "ok"
            assert "yara_scan" in result["data"]
            yara = result["data"]["yara_scan"]
            assert yara["status"] == "ok"
            assert "matched" in yara
            assert "matches" in yara
            assert "rules_loaded" in yara
        finally:
            os.unlink(path)

    def test_yara_scan_detects_credential_theft(self):
        """extract_file_features 对 mimikatz 文件应检测到凭证窃取。"""
        from app.tools.file_analysis import extract_file_features

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("mimikatz lsass sam dump sekurlsa")
            path = f.name
        try:
            result = extract_file_features(path)
            yara = result["data"]["yara_scan"]
            assert yara["matched"] is True
            rule_names = [m["rule_name"] for m in yara["matches"]]
            assert "Credential_Theft_Indicators" in rule_names
        finally:
            os.unlink(path)
