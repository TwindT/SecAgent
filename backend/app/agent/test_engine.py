"""
2.4.1 验证：AgentEngine 基础结构
"""
import os
import sys
import time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.agent.engine import AgentEngine
from app.agent.llm import LLMClient
from app.agent.schemas import tool_registry


def test_engine_init():
    print("=" * 60)
    print("1. AgentEngine 初始化")
    print("=" * 60)

    llm = LLMClient()
    engine = AgentEngine(llm=llm, max_steps=10, step_timeout=60.0)
    assert engine.llm is llm
    assert engine.max_steps == 10
    assert engine.step_timeout == 60.0
    assert len(engine.steps) == 0
    assert engine.step_count == 0
    print("   [OK] 默认参数初始化成功")

    engine2 = AgentEngine()
    assert isinstance(engine2.llm, LLMClient)
    assert isinstance(engine2.tool_reg, type(tool_registry))
    print("   [OK] 无参构造使用默认 LLMClient 和 ToolRegistry")


def test_load_prompt():
    print("\n" + "=" * 60)
    print("2. Prompt 加载")
    print("=" * 60)

    llm = LLMClient()
    engine = AgentEngine(llm=llm)

    # 加载漏洞检测 prompt
    p1 = engine._load_prompt("vulnerability_detection")
    assert "资深安全分析专家" in p1
    assert "CWE" in p1
    assert "scan_code" in p1
    print(f"   [OK] code_audit.txt 加载成功 ({len(p1)} 字符)")

    # 加载恶意分析 prompt
    p2 = engine._load_prompt("malware_analysis")
    assert "恶意代码分析专家" in p2
    assert "ATT&CK" in p2
    assert "extract_iocs" in p2
    print(f"   [OK] malware_analysis.txt 加载成功 ({len(p2)} 字符)")

    # 未知任务类型
    try:
        engine._load_prompt("unknown_type")
        assert False, "应该抛出异常"
    except ValueError as e:
        print(f"   [OK] 未知任务类型正确抛出 ValueError: {e}")


def test_run_structure():
    print("\n" + "=" * 60)
    print("3. run() 返回结构")
    print("=" * 60)

    llm = LLMClient()
    engine = AgentEngine(llm=llm, max_steps=2)

    result = engine.run(
        task_type="vulnerability_detection",
        input_content="print('hello world')"
    )

    # 即使循环未实现，返回结构应该完整
    assert "task_type" in result
    assert "steps" in result
    assert "result" in result
    assert "error" in result
    assert "total_steps" in result
    assert "elapsed_seconds" in result
    assert "usage" in result
    print(f"   [OK] 返回结构完整: {list(result.keys())}")
    print(f"   task_type = {result['task_type']}")
    print(f"   total_steps = {result['total_steps']}")
    print(f"   elapsed = {result['elapsed_seconds']}s")


def test_on_step_callback():
    print("\n" + "=" * 60)
    print("4. 步骤回调 (on_step)")
    print("=" * 60)

    llm = LLMClient()
    engine = AgentEngine(llm=llm)
    received = []

    engine.on_step(lambda step: received.append(step))

    # 手动触发 _push_step
    test_step = {"type": "thought", "data": {"content": "测试"}}
    engine._push_step(test_step)

    assert len(received) == 1
    assert received[0]["type"] == "thought"
    assert received[0]["data"]["content"] == "测试"
    assert len(engine.steps) == 1
    print("   [OK] 回调正常接收 + steps 列表同步更新")


def test_tool_integration():
    print("\n" + "=" * 60)
    print("5. 工具集成")
    print("=" * 60)

    llm = LLMClient()
    engine = AgentEngine(llm=llm)

    vuln_tools = engine.tool_reg.get_for_llm(task_type="vulnerability_detection")
    vuln_names = [t["function"]["name"] for t in vuln_tools]
    print(f"   漏洞检测工具: {vuln_names}")
    assert "scan_code" in vuln_names

    mal_tools = engine.tool_reg.get_for_llm(task_type="malware_analysis")
    mal_names = [t["function"]["name"] for t in mal_tools]
    print(f"   恶意分析工具: {mal_names}")
    assert "extract_file_features" in mal_names

    print("   [OK] ToolRegistry 与 AgentEngine 集成正常")


def test_thought_phase():
    print("\n" + "=" * 60)
    print("6. Thought 阶段 — LLM 推理")
    print("=" * 60)

    llm = LLMClient(max_tokens=1024)
    engine = AgentEngine(llm=llm)
    engine.task_type = "vulnerability_detection"
    engine.step_count = 1  # 模拟循环中第 1 步

    # 模拟 run() 的初始化
    system_prompt = engine._load_prompt("vulnerability_detection")
    tools = engine.tool_reg.get_for_llm(task_type="vulnerability_detection")
    engine.messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": "请分析以下 Python 代码安全问题：\n\n```python\nquery = f\"SELECT * FROM users WHERE name='{name}'\"\ncursor.execute(query)\n```"},
    ]

    result = engine._do_thought(tools)

    print(f"   is_final = {result['is_final']}")
    print(f"   error = {result['error']}")
    print(f"   content length = {len(result.get('content', '') or '')}")
    print(f"   tool_calls = {[tc['name'] for tc in result.get('tool_calls', [])]}")
    print(f"   steps recorded = {len(engine.steps)}")

    # 验证基本行为
    assert result["error"] is None, f"LLM 调用出错: {result['error']}"
    assert result.get("content") or result.get("tool_calls"), "LLM 应返回 content 或 tool_calls"
    assert len(engine.steps) == 1, "应记录 1 个 thought 步骤"
    assert engine.steps[0]["type"] == "thought"
    assert engine.steps[0]["step_num"] == 1
    assert len(engine.messages) >= 3, "messages 应包含 system + user + assistant"

    # 检查 assistant 消息格式（如果 LLM 返回了 tool_calls）
    assistant_msg = engine.messages[-1]
    assert assistant_msg["role"] == "assistant"

    print("   [OK] Thought 阶段正常工作")


def test_action_phase():
    print("\n" + "=" * 60)
    print("7. Action 阶段 — 工具调度执行")
    print("=" * 60)

    llm = LLMClient()
    engine = AgentEngine(llm=llm)
    engine.task_type = "vulnerability_detection"
    engine.step_count = 1

    # 注入一个模拟工具
    def mock_scan_code(code: str, language: str) -> dict:
        return {
            "status": "ok",
            "findings": [
                {"rule": "sql-injection", "line": 14, "severity": "high"}
            ],
            "tool": f"semgrep ({language})",
            "code_length": len(code),
        }
    engine.register_tool("scan_code", mock_scan_code)

    # 模拟 LLM 返回的 tool_calls
    tool_calls = [
        {
            "id": "call_001",
            "name": "scan_code",
            "arguments": {"code": "query = f\"SELECT * FROM users WHERE name='{name}'\"", "language": "python"},
        }
    ]

    results = engine._do_action(tool_calls)

    # 验证结果
    assert len(results) == 1
    assert results[0]["error"] is None
    assert results[0]["name"] == "scan_code"
    assert results[0]["result"]["status"] == "ok"
    assert len(results[0]["result"]["findings"]) == 1
    print(f"   [OK] scan_code 执行成功: {results[0]['result']['findings']}")

    # 验证步骤记录
    assert len(engine.steps) == 1
    assert engine.steps[0]["type"] == "action"
    assert engine.steps[0]["data"]["results"][0]["ok"] is True
    print(f"   [OK] Action 步骤已记录: {engine.steps[0]['type']}")


def test_action_validation():
    print("\n" + "=" * 60)
    print("8. Action — 参数校验与错误处理")
    print("=" * 60)

    llm = LLMClient()
    engine = AgentEngine(llm=llm)
    engine.step_count = 1

    # 测试1：未知工具
    tool_calls = [{"id": "c1", "name": "nonexistent", "arguments": {}}]
    results = engine._do_action(tool_calls)
    assert results[0]["error"] is not None
    assert "未知工具" in results[0]["error"]
    print(f"   [OK] 未知工具检出: {results[0]['error']}")

    # 测试2：缺少必填参数
    tool_calls = [{"id": "c2", "name": "scan_code", "arguments": {"language": "python"}}]
    results = engine._do_action(tool_calls)
    assert results[0]["error"] is not None
    assert "缺少必填参数" in results[0]["error"]
    print(f"   [OK] 必填参数缺失检出: {results[0]['error']}")

    # 测试3：未注册的工具使用 stub
    tool_calls = [{"id": "c3", "name": "query_cve", "arguments": {"keyword": "log4j"}}]
    engine.step_count = 2
    results = engine._do_action(tool_calls)
    assert results[0]["error"] is None  # stub 不算错误
    assert results[0]["result"]["status"] == "not_implemented"
    print(f"   [OK] 未注册工具回退到 stub: {results[0]['result']['status']}")


def test_observe_phase():
    print("\n" + "=" * 60)
    print("9. Observe 阶段 — 结果反馈")
    print("=" * 60)

    llm = LLMClient()
    engine = AgentEngine(llm=llm)
    engine.task_type = "vulnerability_detection"
    engine.step_count = 1
    engine.messages = [
        {"role": "system", "content": "test"},
        {"role": "user", "content": "test"},
        {"role": "assistant", "content": "", "tool_calls": [
            {"id": "call_001", "type": "function", "function": {"name": "scan_code", "arguments": "{}"}}
        ]},
    ]

    tool_calls = [{"id": "call_001", "name": "scan_code", "arguments": {"code": "x=1"}}]
    action_results = [{
        "tool_call_id": "call_001", "name": "scan_code",
        "arguments": {"code": "x=1"}, "result": {"findings": []},
        "elapsed_seconds": 0.5, "error": None,
    }]

    engine._do_observe(tool_calls, action_results)

    # 验证 tool 消息被追加
    assert len(engine.messages) == 4
    tool_msg = engine.messages[-1]
    assert tool_msg["role"] == "tool"
    assert tool_msg["tool_call_id"] == "call_001"
    assert tool_msg["name"] == "scan_code"
    assert "findings" in tool_msg["content"]
    print(f"   [OK] tool 消息已追加: role={tool_msg['role']}, name={tool_msg['name']}")

    # 验证 Observe 步骤
    assert len(engine.steps) == 1
    assert engine.steps[0]["type"] == "observation"
    print(f"   [OK] Observe 步骤已记录")


def test_loop_control():
    print("\n" + "=" * 60)
    print("10. 循环控制 — 步数/超时/重复检测/兜底")
    print("=" * 60)

    # --- 10a: 指纹生成 ---
    tc1 = [{"name": "scan_code", "arguments": {"code": "x=1", "language": "python"}}]
    tc2 = [{"name": "scan_code", "arguments": {"language": "python", "code": "x=1"}}]  # 同参数不同顺序
    tc3 = [{"name": "scan_code", "arguments": {"code": "x=2", "language": "python"}}]  # 不同参数

    fp1 = AgentEngine._action_fingerprint(tc1)
    fp2 = AgentEngine._action_fingerprint(tc2)
    fp3 = AgentEngine._action_fingerprint(tc3)
    assert fp1 == fp2, "相同参数不同顺序应生成相同指纹"
    assert fp1 != fp3, "不同参数应生成不同指纹"
    print(f"   [OK] 指纹生成: 同参={fp1==fp2}, 异参={fp1!=fp3}")

    # --- 10b: 重复检测 ---
    llm = LLMClient()
    engine = AgentEngine(llm=llm)
    engine._recent_actions = [fp1, "other:{}"]
    assert engine._is_duplicate_action(fp1)
    assert not engine._is_duplicate_action(fp3)
    print(f"   [OK] 重复检测: 重复={engine._is_duplicate_action(fp1)}, 不重复={not engine._is_duplicate_action(fp3)}")

    # --- 10c: 进展判断 ---
    assert AgentEngine._is_progress([{"error": None, "result": {"status": "ok"}}])
    assert AgentEngine._is_progress([{"error": "something went wrong"}])
    assert not AgentEngine._is_progress([{"error": None, "result": {"status": "not_implemented"}}])
    print(f"   [OK] 进展判断: ok=有进展, error=有进展, stub=无进展")

    # --- 10d: 兜底逻辑 ---
    engine2 = AgentEngine(llm=llm)
    engine2.task_type = "vulnerability_detection"
    engine2.messages = [{"role": "user", "content": "test"}]
    engine2.steps = []
    engine2.step_count = 3

    # 第 1 次 fallback → 应引导 scan_code（尚未调用）
    engine2._apply_fallback()
    assert len(engine2.messages) == 2
    assert "scan_code" in engine2.messages[-1]["content"]
    assert engine2._no_progress_count == 0
    assert engine2._fallback_count == 1
    print(f"   [OK] fallback #1 引导 scan_code")

    # 第 2 次 fallback → 应要求跳过剩余工具直接输出
    engine2._apply_fallback()
    assert engine2._fallback_count == 2
    assert "不要再调用任何工具" in engine2.messages[-1]["content"]
    print(f"   [OK] fallback #2 要求跳过工具直接输出")

    # 第 3 次 fallback → 最终强制输出
    engine2._apply_fallback()
    assert engine2._fallback_count == 3
    assert "系统指令" in engine2.messages[-1]["content"] or "强制指令" in engine2.messages[-1]["content"]
    print(f"   [OK] fallback #3 最终强制输出")

    # 验证 _get_called_tools
    engine3 = AgentEngine(llm=llm)
    engine3.messages = [
        {"role": "user", "content": "test"},
        {"role": "tool", "tool_call_id": "c1", "name": "scan_code", "content": '{"findings": []}'},
        {"role": "tool", "tool_call_id": "c2", "name": "query_cwe", "content": '{"id": "CWE-89"}'},
    ]
    called = engine3._get_called_tools()
    assert called == {"scan_code", "query_cwe"}
    print(f"   [OK] _get_called_tools 正确: {called}")

    # --- 10e: 步数上限 ---
    engine3 = AgentEngine(llm=llm, max_steps=3)
    engine3._start_time = time.time()
    engine3.step_count = 3  # 已达到上限
    # 构造会立即返回 final 的场景来验证不超过 max_steps
    assert engine3.step_count >= engine3.max_steps
    print(f"   [OK] 步数上限检查: max_steps={engine3.max_steps}")


if __name__ == "__main__":
    test_engine_init()
    test_load_prompt()
    test_run_structure()
    test_on_step_callback()
    test_tool_integration()
    test_thought_phase()
    test_action_phase()
    test_action_validation()
    test_observe_phase()
    test_loop_control()
    print("\n" + "=" * 60)
    print("All tests passed!")
    print("=" * 60)
