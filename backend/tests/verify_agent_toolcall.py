"""3.6.4 Agent Function Calling 联调验证脚本。

模拟 LLM 返回 tool_calls，通过 AgentEngine._do_action 调度执行，
验证全部 7 个已注册的工具可正常返回。
"""

import tempfile
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from app.agent.engine import AgentEngine
from app.tools import (
    scan_code, query_cve, query_cwe, extract_file_features,
    extract_iocs, query_threat_intel, map_attack, scan_yara,
)

SQL_INJECTION_CODE = '''query = "SELECT * FROM users WHERE name = '" + username + "'"
cursor.execute(query)'''

SUSPICIOUS_TEXT = (
    "mimikatz lsass sam dump credential theft at https://evil.com "
    "keylogger GetAsyncKeyState encrypt ransom bitcoin BTC"
)


def main():
    # 创建测试文件
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write(SUSPICIOUS_TEXT)
        text_file = f.name

    try:
        # 创建引擎并注册所有工具
        engine = AgentEngine(max_steps=5)
        engine.register_tool("scan_code", scan_code)
        engine.register_tool("query_cve", query_cve)
        engine.register_tool("query_cwe", query_cwe)
        engine.register_tool("extract_file_features", extract_file_features)
        engine.register_tool("extract_iocs", extract_iocs)
        engine.register_tool("query_threat_intel", query_threat_intel)
        engine.register_tool("map_attack", map_attack)
        engine.register_tool("scan_yara", scan_yara)

        print(f"Registered {len(engine._tool_executors)} tool executors\n")

        # 模拟 Function Calling tool_calls
        test_cases = [
            ("scan_code", {
                "code": SQL_INJECTION_CODE,
                "language": "python",
            }),
            ("query_cwe", {"cwe_id": "CWE-89"}),
            ("query_cve", {"keyword": "sql injection"}),
            ("extract_file_features", {"file_path": text_file}),
            ("extract_iocs", {
                "text": "malware at 10.0.0.5 via https://evil.com "
                        "hash abc123def456abc123def456abc123de",
            }),
            ("query_threat_intel", {"ioc_type": "ip", "ioc_value": "8.8.8.8"}),
            ("map_attack", {"behavior": "credential dumping keylogging backdoor"}),
            ("scan_yara", {"file_path": text_file}),
        ]

        all_ok = True
        for name, args in test_cases:
            tool_calls = [{"id": "call_1", "name": name, "arguments": args}]
            results = engine._do_action(tool_calls)
            r = results[0]
            ok = r["error"] is None
            result = r.get("result", {})
            status = result.get("status", "N/A")
            if not ok:
                all_ok = False
            print(f"  {name:28s} ok={ok}   status={status}")

        print(f"\n{'ALL 8 TOOLS PASSED' if all_ok else 'SOME FAILED'}")
        return 0 if all_ok else 1

    finally:
        os.unlink(text_file)


if __name__ == "__main__":
    sys.exit(main())
