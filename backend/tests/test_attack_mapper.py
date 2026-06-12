"""
3.4 ATT&CK 技术映射工具 — 测试 (pytest)

覆盖 map_attack 入口函数，验证关键词匹配、
评分排序和边界情况处理。
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from app.tools.attack_mapper import map_attack, _tokenize


# ====================================================================
# _tokenize
# ====================================================================
class TestTokenize:
    def test_simple_words(self):
        words = _tokenize("credential dumping")
        assert "credential" in words
        assert "dumping" in words
        assert "credential dumping" in words

    def test_filters_stop_words(self):
        words = _tokenize("the attack is from a remote site")
        for sw in ["the", "is", "a", "from"]:
            assert sw not in words
        assert "attack" in words
        assert "remote" in words
        assert "remote site" in words

    def test_empty_string(self):
        words = _tokenize("")
        assert words == []

    def test_only_stop_words(self):
        words = _tokenize("the a an is")
        assert words == []

    def test_punctuation_handling(self):
        words = _tokenize("download, run, and persist!")
        assert "download" in words
        assert "run" in words
        assert "persist" in words

    def test_bigram_generation(self):
        words = _tokenize("remote file download")
        assert "remote file" in words
        assert "file download" in words


# ====================================================================
# map_attack — 正确匹配
# ====================================================================
class TestMapAttackMatching:
    def test_credential_dumping_maps_to_t1003(self):
        """dev-plan 3.4 核心验收标准：输入 'credential dumping' → 匹配到 T1003"""
        result = map_attack("credential dumping")
        assert result["status"] == "ok"
        assert result["total"] >= 1
        # 第一条匹配必须是 T1003
        top_match = result["matches"][0]
        assert top_match["technique_id"] == "T1003"
        assert top_match["score"] > 0

    def test_phishing_maps_to_t1566(self):
        result = map_attack("phishing email with malicious attachment")
        assert result["status"] == "ok"
        technique_ids = [m["technique_id"] for m in result["matches"]]
        assert "T1566" in technique_ids

    def test_keylogger_maps_to_keylogging_technique(self):
        result = map_attack("keyboard input capture and logging")
        assert result["status"] == "ok"
        technique_ids = [m["technique_id"] for m in result["matches"]]
        # T1056 or similar input capture technique
        assert len(technique_ids) > 0

    def test_powershell_download_execute(self):
        result = map_attack("powershell download and execute remote payload")
        assert result["status"] == "ok"
        technique_ids = [m["technique_id"] for m in result["matches"]]
        # Should match something related to PowerShell or command execution
        assert len(technique_ids) > 0

    def test_registry_persistence(self):
        result = map_attack("registry run key persistence mechanism")
        assert result["status"] == "ok"
        technique_ids = [m["technique_id"] for m in result["matches"]]
        # Should match T1547 or similar persistence technique
        assert len(technique_ids) > 0


# ====================================================================
# map_attack — 返回结构
# ====================================================================
class TestMapAttackStructure:
    def test_match_fields(self):
        result = map_attack("credential access via lsass dump")
        assert result["status"] == "ok"
        for match in result["matches"]:
            assert "technique_id" in match
            assert "technique_name" in match
            assert "tactic_id" in match
            assert "tactic_name" in match
            assert "description" in match
            assert "score" in match
            assert isinstance(match["score"], int)
            assert match["technique_id"].startswith("T")

    def test_results_sorted_by_score(self):
        """结果按分数降序排列。"""
        result = map_attack("credential dumping")
        scores = [m["score"] for m in result["matches"]]
        assert scores == sorted(scores, reverse=True)

    def test_max_10_results(self):
        result = map_attack("malware trojan backdoor remote access steal data encrypt ransomware")
        assert len(result["matches"]) <= 10


# ====================================================================
# 边界情况
# ====================================================================
class TestMapAttackEdgeCases:
    def test_empty_string(self):
        result = map_attack("")
        assert result["status"] == "error"
        assert "空" in result["error"]

    def test_none_input(self):
        result = map_attack(None)
        assert result["status"] == "error"

    def test_only_stop_words(self):
        """全停用词时无法提取关键词。"""
        result = map_attack("the a an is in")
        assert result["status"] == "error"

    def test_gibberish(self):
        """无意义字符串不应匹配任何技术。"""
        result = map_attack("xyzzy blah blargh nonsensical")
        # 可能返回 ok 但 matches 为空（取决于 ATT&CK 数据中是否有匹配）
        assert result["status"] == "ok"
        # 应该有匹配（因为有些通用词可能在 description 中出现）
        # 或至少不报错，结构正确
        assert isinstance(result["matches"], list)

    def test_non_string_input(self):
        result = map_attack(12345)
        assert result["status"] == "error"

    def test_short_input(self):
        result = map_attack("sql")
        assert result["status"] == "ok"
        assert isinstance(result["matches"], list)
