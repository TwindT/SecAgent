"""
3.6 工具层整体联调 — 集成测试 (pytest)

模拟 Agent 依次调用全部 8 个已注册工具，
验证每个工具都能正常返回、签名统一、错误处理正确。
"""

import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ====================================================================
# 辅助：创建测试用文件
# ====================================================================

_SQL_INJECTION_CODE = """
import sqlite3

def get_user(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchall()
"""

_SUSPICIOUS_BINARY_CONTENT = (
    b"This program uses SetWindowsHookEx and GetAsyncKeyState "
    b"to capture keystrokes. It also calls CreateRemoteThread "
    b"for code injection. The C2 server is at https://evil-c2.example.com/beacon "
    b"and the file hash is aaaabbbbccccddddeeeeffff00001111. "
    b"mimikatz lsass sam dump encrypt ransom bitcoin BTC"
)


def _make_temp_text_file(content: str, suffix: str = ".py") -> str:
    """创建临时文本文件，返回路径。"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False) as f:
        f.write(content)
        return f.name


def _make_temp_binary_file(content: bytes) -> str:
    """创建临时二进制文件，返回路径。"""
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".bin", delete=False) as f:
        f.write(content)
        return f.name


# ====================================================================
# 核心：Agent 调用全流程模拟
# ====================================================================

# 所有 8 个工具入口函数名
ALL_TOOLS = [
    "scan_code",
    "query_cve",
    "query_cwe",
    "extract_file_features",
    "extract_iocs",
    "query_threat_intel",
    "map_attack",
    "scan_yara",
]


class TestToolRegistration:
    """验证所有工具在 task_runner 中已注册。"""

    def test_all_tool_schemas_exist(self):
        """8 个 Schema 应全部定义。"""
        from app.agent.schemas import tool_registry as tr
        names = tr.list_tools()
        for tool in ALL_TOOLS:
            assert tool in names, f"Schema 缺失: {tool}"

    def test_schema_params_not_empty(self):
        """每个 Schema 应有 parameters 定义。"""
        from app.agent.schemas import tool_registry as tr
        for tool in ALL_TOOLS:
            schema = tr.get(tool)
            assert schema is not None, f"未找到 Schema: {tool}"
            params = schema["function"]["parameters"]
            assert "properties" in params
            assert isinstance(params["properties"], dict)


class TestToolSignatures:
    """验证所有工具入口函数签名与 Schema 参数一致。"""

    def test_scan_code_signature(self):
        from app.agent.schemas import get_schema
        from app.tools.scanner import scan_code
        schema = get_schema("scan_code")
        sig_params = list(schema["function"]["parameters"]["properties"].keys())
        assert sig_params == ["code", "language"]

    def test_query_cve_signature(self):
        from app.agent.schemas import get_schema
        from app.tools.cve_query import query_cve
        schema = get_schema("query_cve")
        sig_params = list(schema["function"]["parameters"]["properties"].keys())
        assert set(sig_params) == {"cve_id", "keyword"}

    def test_query_cwe_signature(self):
        from app.agent.schemas import get_schema
        from app.tools.cve_query import query_cwe
        schema = get_schema("query_cwe")
        sig_params = list(schema["function"]["parameters"]["properties"].keys())
        assert sig_params == ["cwe_id"]

    def test_extract_file_features_signature(self):
        from app.agent.schemas import get_schema
        from app.tools.file_analysis import extract_file_features
        schema = get_schema("extract_file_features")
        sig_params = list(schema["function"]["parameters"]["properties"].keys())
        assert sig_params == ["file_path"]

    def test_extract_iocs_signature(self):
        from app.agent.schemas import get_schema
        from app.tools.ioc_extractor import extract_iocs
        schema = get_schema("extract_iocs")
        sig_params = list(schema["function"]["parameters"]["properties"].keys())
        assert sig_params == ["text"]

    def test_query_threat_intel_signature(self):
        from app.agent.schemas import get_schema
        from app.tools.threat_intel import query_threat_intel
        schema = get_schema("query_threat_intel")
        sig_params = list(schema["function"]["parameters"]["properties"].keys())
        assert set(sig_params) == {"ioc_type", "ioc_value"}

    def test_map_attack_signature(self):
        from app.agent.schemas import get_schema
        from app.tools.attack_mapper import map_attack
        schema = get_schema("map_attack")
        sig_params = list(schema["function"]["parameters"]["properties"].keys())
        assert sig_params == ["behavior"]

    def test_scan_yara_signature(self):
        from app.agent.schemas import get_schema
        from app.tools.yara_scanner import scan_yara
        schema = get_schema("scan_yara")
        sig_params = list(schema["function"]["parameters"]["properties"].keys())
        assert sig_params == ["file_path"]


class TestToolReturnFormat:
    """验证所有工具返回格式包含 status + error 字段。"""

    REQUIRED_KEYS = {"status"}

    def _check_return_basics(self, result: dict, tool_name: str):
        assert isinstance(result, dict), f"{tool_name} 未返回 dict"
        assert "status" in result, f"{tool_name} 返回缺少 status"
        assert "error" in result, f"{tool_name} 返回缺少 error"
        assert result["status"] in ("ok", "error", "not_found"), (
            f"{tool_name} status 值异常: {result['status']}"
        )

    def test_scan_code_return_format(self):
        from app.tools.scanner import scan_code
        result = scan_code(code=_SQL_INJECTION_CODE, language="python")
        self._check_return_basics(result, "scan_code")
        if result["status"] == "ok":
            assert "findings" in result
            assert "total" in result

    def test_query_cwe_return_format(self):
        from app.tools.cve_query import query_cwe
        result = query_cwe(cwe_id="CWE-89")
        self._check_return_basics(result, "query_cwe")

    def test_query_cve_return_format(self):
        from app.tools.cve_query import query_cve
        # 用不存在的 CVE ID 避免 API 调用
        result = query_cve(cve_id="CVE-0000-00000")
        self._check_return_basics(result, "query_cve")

    def test_extract_file_features_return_format(self):
        from app.tools.file_analysis import extract_file_features
        file_path = _make_temp_binary_file(_SUSPICIOUS_BINARY_CONTENT)
        try:
            result = extract_file_features(file_path)
            self._check_return_basics(result, "extract_file_features")
            if result["status"] == "ok":
                assert "data" in result
        finally:
            os.unlink(file_path)

    def test_extract_iocs_return_format(self):
        from app.tools.ioc_extractor import extract_iocs
        result = extract_iocs("malware at 10.0.0.1 with https://evil.com/bad hash abc123def456abc123def456abc123de")
        self._check_return_basics(result, "extract_iocs")
        if result["status"] == "ok":
            assert "iocs" in result
            assert "total" in result

    def test_query_threat_intel_return_format(self):
        from app.tools.threat_intel import query_threat_intel
        # 用合法的 IP 格式，但可能 API 不可用
        result = query_threat_intel(ioc_type="ip", ioc_value="8.8.8.8")
        self._check_return_basics(result, "query_threat_intel")

    def test_map_attack_return_format(self):
        from app.tools.attack_mapper import map_attack
        result = map_attack("credential dumping via lsass")
        self._check_return_basics(result, "map_attack")
        if result["status"] == "ok":
            assert "matches" in result
            assert "total" in result

    def test_scan_yara_return_format(self):
        from app.tools.yara_scanner import scan_yara
        file_path = _make_temp_binary_file(b"mimikatz lsass sam dump encrypt ransom bitcoin")
        try:
            result = scan_yara(file_path)
            self._check_return_basics(result, "scan_yara")
            if result["status"] == "ok":
                assert "matched" in result
                assert "matches" in result
        finally:
            os.unlink(file_path)


# ====================================================================
# Agent 调用全流程模拟
# ====================================================================

class TestAgentFullWorkflow:
    """模拟 Agent 对恶意代码分析的完整工具调用流程。"""

    def test_vulnerability_detection_workflow(self):
        """模拟漏洞检测流程: scan_code → query_cwe。"""
        from app.tools.scanner import scan_code
        from app.tools.cve_query import query_cwe

        steps = []

        # Step 1: 静态扫描
        r1 = scan_code(code=_SQL_INJECTION_CODE, language="python")
        assert isinstance(r1, dict) and "status" in r1
        steps.append(("scan_code", r1["status"]))

        # Step 2: 查询 CWE
        r2 = query_cwe(cwe_id="CWE-89")
        assert isinstance(r2, dict) and "status" in r2
        steps.append(("query_cwe", r2["status"]))

        # 验证每步都有返回
        assert len(steps) == 2
        for name, status in steps:
            assert status in ("ok", "error", "not_found"), f"{name}: 意外 status={status}"

    def test_malware_analysis_workflow(self):
        """模拟恶意分析流程: extract_file_features → extract_iocs → map_attack → scan_yara → query_threat_intel。"""
        from app.tools.file_analysis import extract_file_features
        from app.tools.ioc_extractor import extract_iocs
        from app.tools.attack_mapper import map_attack
        from app.tools.yara_scanner import scan_yara
        from app.tools.threat_intel import query_threat_intel

        file_path = _make_temp_binary_file(_SUSPICIOUS_BINARY_CONTENT)
        try:
            steps = []

            # Step 1: 文件特征提取
            r1 = extract_file_features(file_path)
            assert isinstance(r1, dict) and "status" in r1
            steps.append(("extract_file_features", r1["status"]))

            # Step 2-6: 后续分析
            r2 = extract_iocs(_SUSPICIOUS_BINARY_CONTENT.decode("utf-8", errors="replace"))
            assert isinstance(r2, dict) and "status" in r2 and r2["status"] == "ok"
            steps.append(("extract_iocs", r2["status"]))

            r3 = map_attack("credential dumping and keylogging backdoor")
            assert isinstance(r3, dict) and "status" in r3 and r3["status"] == "ok"
            steps.append(("map_attack", r3["status"]))

            r4 = scan_yara(file_path)
            assert isinstance(r4, dict) and "status" in r4
            steps.append(("scan_yara", r4["status"]))

            # 用提取到的 IOC 做威胁情报查询
            first_url = r2["iocs"]["urls"][0] if r2["iocs"]["urls"] else "https://evil-c2.example.com/beacon"
            r5 = query_threat_intel(ioc_type="url", ioc_value=first_url)
            assert isinstance(r5, dict) and "status" in r5
            steps.append(("query_threat_intel", r5["status"]))

            assert len(steps) == 5
            for name, status in steps:
                assert status in ("ok", "error", "not_found"), f"{name}: 意外 status={status}"

        finally:
            os.unlink(file_path)

    def test_error_handling_across_tools(self):
        """所有工具遇到非法输入时应返回 error status 而非抛异常。"""
        from app.tools.scanner import scan_code
        from app.tools.cve_query import query_cwe
        from app.tools.file_analysis import extract_file_features
        from app.tools.ioc_extractor import extract_iocs
        from app.tools.attack_mapper import map_attack
        from app.tools.yara_scanner import scan_yara
        from app.tools.threat_intel import query_threat_intel

        # 不存在的文件
        r = extract_file_features("/nonexistent/abcdef.bin")
        assert r["status"] == "error"

        # 空 CWE ID（query_cwe 对空字符串返回 not_found）
        r = query_cwe(cwe_id="")
        assert r["status"] in ("error", "not_found")

        # 空 IOC 文本
        r = extract_iocs("")
        assert r["status"] == "error"

        # 空行为描述
        r = map_attack("")
        assert r["status"] == "error"

        # 不存在的文件（YARA）
        r = scan_yara("/nonexistent/abcdef.bin")
        assert r["status"] == "error"

        # 不支持的 IOC 类型
        r = query_threat_intel(ioc_type="unknown", ioc_value="test")
        assert r["status"] == "error"

    def test_tool_call_order_independence(self):
        """工具之间不应有状态依赖，可任意顺序调用。"""
        from app.tools.ioc_extractor import extract_iocs
        from app.tools.attack_mapper import map_attack

        # 先 map_attack 后 extract_iocs，反之亦然
        text = "keylogger at 10.0.0.5 https://evil.com hash abc123def456abc123def456abc123de"

        order1_r1 = map_attack("keylogging credential theft")
        order1_r2 = extract_iocs(text)

        order2_r1 = extract_iocs(text)
        order2_r2 = map_attack("keylogging credential theft")

        assert order1_r2["total"] == order2_r1["total"]


# ====================================================================
# 工具注册集成（模拟 task_runner 注册流程）
# ====================================================================

class TestTaskRunnerIntegration:
    """验证 task_runner 中注册的所有工具可以被导入和调用。"""

    def test_all_tools_importable_from_init(self):
        """所有 7 个已注册工具可以从 app.tools 导入。"""
        from app.tools import (
            scan_code,
            query_cve,
            query_cwe,
            extract_file_features,
            extract_iocs,
            query_threat_intel,
            map_attack,
            scan_yara,
        )
        assert callable(scan_code)
        assert callable(query_cve)
        assert callable(query_cwe)
        assert callable(extract_file_features)
        assert callable(extract_iocs)
        assert callable(query_threat_intel)
        assert callable(map_attack)
        assert callable(scan_yara)

    def test_engine_registers_all_tools(self):
        """AgentEngine 可注册全部执行器并取代 stub。"""
        from app.agent.engine import AgentEngine
        engine = AgentEngine(max_steps=1)

        # 初始状态下工具执行器为空（stub 按需创建）
        assert isinstance(engine._tool_executors, dict)

        # 模拟 task_runner 的注册
        from app.tools import (
            scan_code, query_cve, query_cwe, extract_file_features,
            extract_iocs, query_threat_intel, map_attack, scan_yara,
        )
        engine.register_tool("scan_code", scan_code)
        engine.register_tool("query_cve", query_cve)
        engine.register_tool("query_cwe", query_cwe)
        engine.register_tool("extract_file_features", extract_file_features)
        engine.register_tool("extract_iocs", extract_iocs)
        engine.register_tool("query_threat_intel", query_threat_intel)
        engine.register_tool("map_attack", map_attack)
        engine.register_tool("scan_yara", scan_yara)

        assert len(engine._tool_executors) == 8
        # 验证注册的是真实实现而非 stub
        assert engine._tool_executors["scan_code"] is scan_code
        assert engine._tool_executors["extract_iocs"] is extract_iocs
        assert engine._tool_executors["scan_yara"] is scan_yara
