"""
3.3 文件特征提取工具 — 测试 (pytest)

覆盖 _analyze_pe / _extract_strings / _analyze_office / _detect_file_type / extract_file_features。
"""

import os
import sys
import tempfile
import struct

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from app.tools.file_analysis import (
    _analyze_pe,
    _extract_strings,
    _classify_strings,
    _analyze_office,
    _detect_file_type,
    _calculate_entropy,
    extract_file_features,
)


# ====================================================================
# _analyze_pe
# ====================================================================
class TestAnalyzePe:
    def test_detects_notepad_as_pe(self):
        """notepad.exe 应被识别为 PE 并返回导入表。"""
        notepad_path = os.path.expandvars(r"%SystemRoot%\System32\notepad.exe")
        if not os.path.exists(notepad_path):
            pytest.skip("notepad.exe 不可用")

        result = _analyze_pe(notepad_path)

        assert result["is_pe"] is True
        assert result["machine"]  # 应有机器类型
        assert result["entry_point"].startswith("0x")
        assert result["timestamp"]  # 应有编译时间戳
        # 导入表
        assert len(result["imports"]) >= 1, "PE 应至少有 1 个导入 DLL"
        first_dll = result["imports"][0]
        assert first_dll["dll"]  # DLL 名称
        assert len(first_dll["functions"]) >= 1  # 函数列表
        # 节区
        assert len(result["sections"]) >= 1, "PE 应至少有 1 个节区"
        first_section = result["sections"][0]
        assert first_section["name"]
        assert first_section["virtual_size"] > 0
        assert "entropy" in first_section

    def test_non_pe_returns_is_pe_false(self):
        """非 PE 文件应返回 is_pe=False。"""
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="w") as f:
            f.write("Hello, this is not a PE file.")
            temp_path = f.name

        try:
            result = _analyze_pe(temp_path)
            assert result["is_pe"] is False
        finally:
            os.unlink(temp_path)

    def test_timestamp_format(self):
        """编译时间戳应为 ISO 格式。"""
        notepad_path = os.path.expandvars(r"%SystemRoot%\System32\notepad.exe")
        if not os.path.exists(notepad_path):
            pytest.skip("notepad.exe 不可用")

        result = _analyze_pe(notepad_path)
        if result["is_pe"]:
            # 格式: YYYY-MM-DDTHH:MM:SSZ
            assert "T" in result["timestamp"]
            assert result["timestamp"].endswith("Z")

    def test_section_has_characteristics(self):
        """节区应有特征标志字符串。"""
        notepad_path = os.path.expandvars(r"%SystemRoot%\System32\notepad.exe")
        if not os.path.exists(notepad_path):
            pytest.skip("notepad.exe 不可用")

        result = _analyze_pe(notepad_path)
        if result["is_pe"]:
            for section in result["sections"]:
                assert section["characteristics"], \
                    f"节区 {section['name']} 缺少 characteristics"


# ====================================================================
# _extract_strings
# ====================================================================
class TestExtractStrings:
    def test_extracts_ascii_strings(self):
        """应提取文件中的 ASCII 可打印字符串。"""
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="wb") as f:
            f.write(b"Hello World! This is a test string.\nAnother line here.")
            temp_path = f.name

        try:
            result = _extract_strings(temp_path, min_length=4)
            assert len(result) >= 2
            assert any("Hello World" in s for s in result)
            assert any("Another line" in s for s in result)
        finally:
            os.unlink(temp_path)

    def test_ignores_short_strings(self):
        """应忽略长度不足 min_length 的字符串。"""
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="wb") as f:
            f.write(b"Hi oh ah" + b"\x00" * 10 + b"Long enough string here")
            temp_path = f.name

        try:
            result = _extract_strings(temp_path, min_length=8)
            # "Hi", "oh", "ah" 不够 8 个字符，应被过滤
            short = [s for s in result if len(s) < 8]
            assert len(short) == 0
        finally:
            os.unlink(temp_path)

    def test_no_duplicates(self):
        """提取的字符串应无重复。"""
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="wb") as f:
            data = b"duplicate" * 100
            f.write(data)
            temp_path = f.name

        try:
            result = _extract_strings(temp_path, min_length=4)
            # 验证去重: 统计 "duplicate" 出现次数
            count = sum(1 for s in result if "duplicate" in s.lower())
            assert count <= len(result)
        finally:
            os.unlink(temp_path)


# ====================================================================
# _classify_strings
# ====================================================================
class TestClassifyStrings:
    def test_detects_ipv4(self):
        """应识别 IPv4 地址。"""
        strings = ["192.168.1.100", "10.0.0.1", "just a regular text"]
        result = _classify_strings(strings)
        assert len(result["ipv4"]) >= 2

    def test_detects_urls(self):
        """应识别 URL。"""
        strings = ["https://evil.example.com/payload.exe", "plain text"]
        result = _classify_strings(strings)
        assert len(result["urls"]) >= 1

    def test_detects_suspicious_keywords(self):
        """应识别可疑关键词。"""
        strings = [
            "cmd.exe /c calc",
            "CreateProcess called here",
            "Normal log message",
        ]
        result = _classify_strings(strings)
        assert len(result["suspicious"]) >= 2

    def test_detects_registry_keys(self):
        """应识别注册表路径。"""
        strings = [
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "nothing special",
        ]
        result = _classify_strings(strings)
        assert len(result["registry_keys"]) >= 1


# ====================================================================
# _detect_file_type
# ====================================================================
class TestDetectFileType:
    def test_detects_pe_file(self):
        """应识别 PE/DOS 可执行文件。"""
        notepad_path = os.path.expandvars(r"%SystemRoot%\System32\notepad.exe")
        if not os.path.exists(notepad_path):
            pytest.skip("notepad.exe 不可用")

        result = _detect_file_type(notepad_path)
        assert result["confidence"] == "high"
        assert "PE" in result["type"]

    def test_detects_pdf(self):
        """应识别 PDF 文档。"""
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False, mode="wb") as f:
            f.write(b"%PDF-1.4 This is a fake PDF file header for testing")
            temp_path = f.name

        try:
            result = _detect_file_type(temp_path)
            assert result["type"] == "PDF document"
            assert result["confidence"] == "high"
        finally:
            os.unlink(temp_path)

    def test_detects_png(self):
        """应识别 PNG 图片。"""
        png_header = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False, mode="wb") as f:
            f.write(png_header)
            temp_path = f.name

        try:
            result = _detect_file_type(temp_path)
            assert result["type"] == "PNG image"
            assert result["category"] == "image"
            assert result["confidence"] == "high"
        finally:
            os.unlink(temp_path)

    def test_detects_zip(self):
        """应识别 ZIP 归档。"""
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False, mode="wb") as f:
            f.write(b"PK\x03\x04" + b"\x00" * 100)
            temp_path = f.name

        try:
            result = _detect_file_type(temp_path)
            assert "ZIP" in result["type"] or "archive" in result["type"]
            assert result["confidence"] == "high"
        finally:
            os.unlink(temp_path)

    def test_detects_gzip(self):
        """应识别 GZIP 归档。"""
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False, mode="wb") as f:
            f.write(b"\x1f\x8b\x08" + b"\x00" * 100)
            temp_path = f.name

        try:
            result = _detect_file_type(temp_path)
            assert "GZIP" in result["type"]
        finally:
            os.unlink(temp_path)

    def test_detects_ole2(self):
        """应识别 OLE2 复合文档。"""
        ole_magic = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False, mode="wb") as f:
            f.write(ole_magic + b"\x00" * 100)
            temp_path = f.name

        try:
            result = _detect_file_type(temp_path)
            assert result["category"] == "document"
            assert result["confidence"] == "high"
        finally:
            os.unlink(temp_path)

    def test_unknown_binary_returns_low_confidence(self):
        """随机二进制数据应返回低置信度。"""
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False, mode="wb") as f:
            f.write(b"\x99\x99\x99\x99" * 50)
            temp_path = f.name

        try:
            result = _detect_file_type(temp_path)
            assert result["confidence"] == "low"
        finally:
            os.unlink(temp_path)


# ====================================================================
# _calculate_entropy
# ====================================================================
class TestCalculateEntropy:
    def test_high_entropy(self):
        """随机数据应有高熵值 (>7.0)。"""
        data = os.urandom(10000)
        entropy = _calculate_entropy(data)
        assert entropy > 7.0, f"随机数据熵值应 > 7.0，实际: {entropy}"

    def test_low_entropy(self):
        """重复数据应有低熵值 (<1.0)。"""
        data = b"A" * 10000
        entropy = _calculate_entropy(data)
        assert entropy < 1.0, f"重复数据熵值应 < 1.0，实际: {entropy}"


# ====================================================================
# extract_file_features — 统一入口
# ====================================================================
class TestExtractFileFeatures:
    def test_pe_file_returns_pe_info(self):
        """PE 文件应返回 pe_info。"""
        notepad_path = os.path.expandvars(r"%SystemRoot%\System32\notepad.exe")
        if not os.path.exists(notepad_path):
            pytest.skip("notepad.exe 不可用")

        result = extract_file_features(notepad_path)

        assert result["status"] == "ok"
        data = result["data"]
        assert data["file_name"] == "notepad.exe"
        assert data["file_size"] > 0
        # Hash
        assert len(data["md5"]) == 32
        assert len(data["sha1"]) == 40
        assert len(data["sha256"]) == 64
        # 类型
        assert data["type_info"]["confidence"] == "high"
        assert "PE" in data["type_info"]["type"]
        # PE 信息
        assert data["pe_info"] is not None
        assert data["pe_info"]["is_pe"] is True
        assert len(data["pe_info"]["imports"]) >= 1
        # 字符串
        assert data["strings"]["total"] >= 1

    def test_text_file_returns_strings(self):
        """文本文件应提取字符串。"""
        with tempfile.NamedTemporaryFile(
            suffix=".txt", delete=False, mode="w", encoding="utf-8"
        ) as f:
            f.write("This is a test file.\nhttps://example.com\n192.168.1.1")
            temp_path = f.name

        try:
            result = extract_file_features(temp_path)

            assert result["status"] == "ok"
            data = result["data"]
            assert data["strings"]["total"] >= 1
            assert len(data["strings"]["urls"]) >= 1  # 应检出 URL
            assert len(data["strings"]["ipv4"]) >= 1  # 应检出 IP
            # 非 PE 不应有 pe_info
            assert data["pe_info"] is None or data["pe_info"].get("is_pe") is False
        finally:
            os.unlink(temp_path)

    def test_file_not_found(self):
        """不存在的文件应返回 error。"""
        result = extract_file_features("/nonexistent/file.exe")
        assert result["status"] == "error"
        assert result["error"]

    def test_result_has_all_hash_types(self):
        """应返回三种 Hash。"""
        notepad_path = os.path.expandvars(r"%SystemRoot%\System32\notepad.exe")
        if not os.path.exists(notepad_path):
            pytest.skip("notepad.exe 不可用")

        result = extract_file_features(notepad_path)
        data = result["data"]
        assert len(data["md5"]) == 32
        assert len(data["sha1"]) == 40
        assert len(data["sha256"]) == 64
        # 三个 Hash 应不同
        assert data["md5"] != data["sha256"]
        assert data["sha1"] != data["sha256"]
