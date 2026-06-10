"""
2.3 验证：测试所有 Schema 定义和 ToolRegistry 功能
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.agent.schemas import (
    SCAN_CODE_SCHEMA,
    QUERY_CVE_SCHEMA,
    QUERY_CWE_SCHEMA,
    EXTRACT_FILE_FEATURES_SCHEMA,
    EXTRACT_IOCS_SCHEMA,
    QUERY_THREAT_INTEL_SCHEMA,
    MAP_ATTACK_SCHEMA,
    SCAN_YARA_SCHEMA,
    CODE_AUDIT_TOOLS,
    MALWARE_ANALYSIS_TOOLS,
    ALL_SCHEMAS,
    get_schema,
    get_schemas_for_task,
    tool_registry,
)


def test_all_schemas():
    print("=" * 60)
    print("1. Schema 完整性检查")
    print("=" * 60)

    all_names = {s["function"]["name"] for s in ALL_SCHEMAS}
    expected = {
        "scan_code", "query_cve", "query_cwe",
        "extract_file_features", "extract_iocs",
        "query_threat_intel", "map_attack", "scan_yara",
    }
    assert all_names == expected, f"Missing schemas: {expected - all_names}"
    print(f"   [OK] 共 {len(ALL_SCHEMAS)} 个 Schema，名称无缺失")

    for s in ALL_SCHEMAS:
        assert s["type"] == "function", f"{s['function']['name']}: type != function"
        func = s["function"]
        assert "name" in func
        assert "description" in func
        assert "parameters" in func
        props = func["parameters"].get("properties", {})
        assert isinstance(props, dict)
        print(f"   [OK] {func['name']} — {len(props)} 个参数")


def test_task_grouping():
    print("\n" + "=" * 60)
    print("2. 任务类型分组")
    print("=" * 60)

    vuln = get_schemas_for_task("vulnerability_detection")
    vuln_names = {s["function"]["name"] for s in vuln}
    assert vuln_names == set(CODE_AUDIT_TOOLS)
    print(f"   漏洞检测工具: {vuln_names}")

    mal = get_schemas_for_task("malware_analysis")
    mal_names = {s["function"]["name"] for s in mal}
    assert mal_names == set(MALWARE_ANALYSIS_TOOLS)
    print(f"   恶意分析工具: {mal_names}")

    # 验证不重叠
    assert vuln_names & mal_names == set()
    print("   [OK] 两组工具无重叠")


def test_tool_registry():
    print("\n" + "=" * 60)
    print("3. ToolRegistry 功能")
    print("=" * 60)

    tr = tool_registry

    # 基础查询
    assert tr.get("scan_code") is not None
    assert tr.get("nonexistent") is None
    print(f"   [OK] 已注册 {len(tr)} 个工具: {tr.list_tools()}")

    # get_for_llm
    vuln_tools = tr.get_for_llm(task_type="vulnerability_detection")
    assert len(vuln_tools) == 3
    print(f"   [OK] vulnerability_detection → {len(vuln_tools)} tools")

    mal_tools = tr.get_for_llm(task_type="malware_analysis")
    assert len(mal_tools) == 5
    print(f"   [OK] malware_analysis → {len(mal_tools)} tools")

    all_tools = tr.get_for_llm()
    assert len(all_tools) == 8
    print(f"   [OK] 全部 → {len(all_tools)} tools")

    # 指定工具名
    subset = tr.get_for_llm(tool_names=["scan_code", "map_attack"])
    assert len(subset) == 2
    print(f"   [OK] 按名称筛选 → {len(subset)} tools")


def test_validation():
    print("\n" + "=" * 60)
    print("4. 参数校验")
    print("=" * 60)

    tr = tool_registry

    # 正确参数
    r = tr.validate_args("scan_code", {"code": "print(1)", "language": "python"})
    assert r["valid"] is True
    print(f"   [OK] scan_code 合法参数通过")

    # 缺少必填参数
    r = tr.validate_args("scan_code", {"code": "print(1)"})
    assert r["valid"] is False
    print(f"   [OK] 缺少必填参数检出: {r['error']}")

    # 枚举值不合法
    r = tr.validate_args("scan_code", {"code": "x", "language": "go"})
    assert r["valid"] is False
    print(f"   [OK] 非法枚举值检出: {r['error']}")

    # 未知工具
    r = tr.validate_args("delete_system32", {})
    assert r["valid"] is False
    print(f"   [OK] 未知工具检出: {r['error']}")

    # threat_intel 枚举
    r = tr.validate_args("query_threat_intel", {"ioc_type": "ip", "ioc_value": "10.0.0.1"})
    assert r["valid"] is True
    print(f"   [OK] query_threat_intel 合法参数通过")

    r = tr.validate_args("query_threat_intel", {"ioc_type": "email", "ioc_value": "a@b.com"})
    assert r["valid"] is False
    print(f"   [OK] query_threat_intel 非法枚举值检出")


def test_llm_format():
    print("\n" + "=" * 60)
    print("5. LLM 兼容格式验证")
    print("=" * 60)

    tools = tool_registry.get_for_llm()
    # 确保每个 tool schema 都能被标准 JSON 序列化
    import json
    dumped = json.dumps(tools, indent=2, ensure_ascii=False)
    reloaded = json.loads(dumped)
    assert len(reloaded) == len(tools)
    print(f"   [OK] 全部 Schema JSON 序列化/反序列化正常 ({len(dumped)} 字符)")


if __name__ == "__main__":
    test_all_schemas()
    test_task_grouping()
    test_tool_registry()
    test_validation()
    test_llm_format()
    print("\n" + "=" * 60)
    print("All tests passed!")
    print("=" * 60)
