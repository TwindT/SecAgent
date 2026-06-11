"""
3.1.5 Agent 命令行 Demo 2.0 — 支持自动类型识别 + 结果聚合 + 置信度

使用方式:
  python demo_cli2.py --file /path/to/sample.js
  python demo_cli2.py --code "os.system('rm -rf /')"
  python demo_cli2.py --file sample.exe --output report.json
  python demo_cli2.py --file sample.py --type vulnerability_detection   # 手动指定类型
"""
import os
import sys
import json
import argparse
import logging
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.agent.llm import LLMClient
from app.agent.engine import AgentEngine

logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

# ==============================================================================
# ANSI 颜色
# ==============================================================================
C = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[91m",
    "green": "\033[92m",
    "yellow": "\033[93m",
    "blue": "\033[94m",
    "cyan": "\033[96m",
    "magenta": "\033[95m",
    "white": "\033[97m",
}


def c(text: str, color: str) -> str:
    return f"{C.get(color, '')}{text}{C['reset']}"


# ==============================================================================
# 工具加载 — 优先真实实现，失败降级为 mock
# ==============================================================================

def _load_real_tools(engine: AgentEngine) -> int:
    """尝试加载真实工具模块，返回成功加载的数量。"""
    count = 0

    # --- scan_code ---
    try:
        from app.tools.scanner import scan_code
        engine.register_tool("scan_code", scan_code)
        logger.info("scan_code: 真实实现已注册")
        count += 1
    except Exception as e:
        logger.warning("scan_code 加载失败: %s", e)

    # --- query_cve ---
    try:
        from app.tools.cve_query import query_cve
        engine.register_tool("query_cve", query_cve)
        logger.info("query_cve: 真实实现已注册")
        count += 1
    except Exception as e:
        logger.warning("query_cve 加载失败: %s", e)

    # --- query_cwe ---
    try:
        from app.tools.cve_query import query_cwe
        engine.register_tool("query_cwe", query_cwe)
        logger.info("query_cwe: 真实实现已注册")
        count += 1
    except Exception as e:
        logger.warning("query_cwe 加载失败: %s", e)

    # --- query_threat_intel ---
    try:
        from app.tools.threat_intel import query_threat_intel
        engine.register_tool("query_threat_intel", query_threat_intel)
        logger.info("query_threat_intel: 真实实现已注册")
        count += 1
    except Exception as e:
        logger.warning("query_threat_intel 加载失败: %s", e)

    return count


def _load_mock_tools(engine: AgentEngine, mock_only: bool = False) -> None:
    """加载 mock 工具（兜底或补充未实现的工具）。

    当 mock_only=True 时，使用纯模拟实现（不尝试调用真实 API）。
    """
    from app.agent.demo_cli import (
        mock_scan_code, mock_query_cwe, mock_query_cve,
        mock_extract_file_features, mock_extract_iocs,
        mock_map_attack, mock_scan_yara,
    )

    if "scan_code" not in engine._tool_executors:
        engine.register_tool("scan_code", mock_scan_code)
    if "query_cwe" not in engine._tool_executors:
        engine.register_tool("query_cwe", mock_query_cwe)
    if "query_cve" not in engine._tool_executors:
        engine.register_tool("query_cve", mock_query_cve)
    if "extract_file_features" not in engine._tool_executors:
        engine.register_tool("extract_file_features", mock_extract_file_features)
    if "extract_iocs" not in engine._tool_executors:
        engine.register_tool("extract_iocs", mock_extract_iocs)
    if "query_threat_intel" not in engine._tool_executors:
        if mock_only:
            engine.register_tool("query_threat_intel", _pure_mock_threat_intel)
        else:
            from app.agent.demo_cli import mock_query_threat_intel
            engine.register_tool("query_threat_intel", mock_query_threat_intel)
    if "map_attack" not in engine._tool_executors:
        engine.register_tool("map_attack", mock_map_attack)
    if "scan_yara" not in engine._tool_executors:
        engine.register_tool("scan_yara", mock_scan_yara)


def _pure_mock_threat_intel(ioc_type: str, ioc_value: str) -> dict:
    """纯模拟威胁情报查询——不尝试调用任何真实 API。"""
    if "evil" in ioc_value.lower() or "malware" in ioc_value.lower():
        return {
            "status": "ok", "ioc_type": ioc_type, "ioc_value": ioc_value,
            "malicious": True, "sources": ["OTX (mock)", "URLhaus (mock)"],
            "pulse_count": 5,
        }
    return {
        "status": "ok", "ioc_type": ioc_type, "ioc_value": ioc_value,
        "malicious": False, "pulse_count": 0,
    }


# ==============================================================================
# 输出渲染
# ==============================================================================

def print_header(text: str) -> None:
    print(f"\n{c('━' * 70, 'dim')}")
    print(f"  {c(text, 'bold')}")
    print(f"{c('━' * 70, 'dim')}\n")


def print_step(step: dict) -> None:
    """渲染单个 ReAct 步骤到终端。"""
    step_num = step.get("step_num", "?")
    step_type = step["type"]
    data = step.get("data", {})

    icons = {
        "thought": (c(" THOUGHT", "cyan"), " "),
        "action": (c(" ACTION ", "yellow"), "  "),
        "observation": (c("OBSERVE ", "green"), "  "),
        "done": (c("  DONE  ", "blue"), " "),
        "error": (c(" ERROR  ", "red"), "  "),
    }
    icon, indent = icons.get(step_type, ("", ""))

    if step_type == "thought":
        content = data.get("content", "")
        tools = data.get("tool_calls_requested", [])
        if content:
            preview = content[:200].replace("\n", " ").strip()
            print(f"  [{icon}] {c(preview, 'dim')}")
        if tools:
            print(f"  {indent}  {c('>>', 'yellow')} 调用工具: {c(', '.join(tools), 'yellow')}")

    elif step_type == "action":
        for r in data.get("results", []):
            status = c("OK", "green") if r.get("ok") else c("FAIL", "red")
            name = r.get("name", "")
            args_preview = ", ".join(f"{k}={str(v)[:40]}" for k, v in r.get("args", {}).items())
            print(f"  [{icon}] {c(name, 'bold')}({args_preview}) {status}")

    elif step_type == "observation":
        for obs in data.get("observations", []):
            preview = obs.get("result_preview", "")[:120]
            tool = obs.get("tool", "")
            print(f"  [{icon}] {c(tool, 'bold')}: {c(preview, 'dim')}")

    elif step_type == "done":
        elapsed = data.get("elapsed_seconds", 0)
        conf = data.get("confidence", "?")
        conf_score = data.get("confidence_score", 0)
        print(f"  [{icon}] 耗时 {c(f'{elapsed}s', 'bold')} | "
              f"置信度: {c(conf.upper(), 'green' if conf == 'high' else 'yellow')} ({conf_score}/100)")

    elif step_type == "error":
        msg = data.get("message", str(data))
        print(f"  [{icon}] {c(msg, 'red')}")


def print_verdict(engine: AgentEngine, result: dict) -> None:
    """打印最终判定和依据。"""
    print_header("分析结果")

    task_type = result.get("task_type", "?")
    detect_reason = result.get("detect_reason", "")
    task_label = {"vulnerability_detection": "代码漏洞检测", "malware_analysis": "恶意代码分析"}
    print(f"  任务类型: {c(task_label.get(task_type, task_type), 'bold')}")
    print(f"  识别原因: {c(detect_reason, 'dim')}")

    if result.get("error"):
        print(f"  {c('ERROR: ' + result['error'], 'red')}")
        return

    # --- 置信度 ---
    confidence = result.get("confidence", {})
    level = confidence.get("level", "?")
    score = confidence.get("score", 0)
    level_color = "green" if level == "high" else ("yellow" if level == "medium" else "red")
    print(f"\n  综合置信度: {c(f'{level.upper()} ({score}/100)', level_color + ' bold')}")

    for factor in confidence.get("factors", []):
        bar = "#" * (factor["score"] // 2) + "-" * ((factor["max"] - factor["score"]) // 2)
        print(f"    {factor['dimension']}: {bar} {factor['score']}/{factor['max']}  {c(factor['detail'], 'dim')}")

    # --- 聚合结果 ---
    aggregated = result.get("aggregated", {})
    summary = aggregated.get("summary", {})
    print(f"\n  工具调用: {c(str(summary.get('total_tool_calls', 0)), 'bold')} 次, "
          f"使用工具: {c(', '.join(summary.get('unique_tools_used', [])), 'cyan')}")

    if task_type == "vulnerability_detection":
        print(f"  扫描发现: {c(str(summary.get('scan_findings_count', 0)), 'red' if summary.get('high_risk_count', 0) > 0 else 'green')} 条"
              f" (高危: {summary.get('high_risk_count', 0)}, "
              f"中危: {summary.get('medium_risk_count', 0)}, "
              f"低危: {summary.get('low_risk_count', 0)})")
    else:
        print(f"  IOC: {c(str(summary.get('iocs_count', 0)), 'bold')} 个 | "
              f"威胁情报: {summary.get('threat_intel_count', 0)} 条 | "
              f"ATT&CK: {summary.get('attack_techniques_count', 0)} 项")

    # --- 总耗时和 Token ---
    print(f"\n  总步数: {c(str(result.get('total_steps', 0)), 'bold')}")
    elapsed_s = str(result.get("elapsed_seconds", 0)) + "s"
    print(f"  总耗时: {c(elapsed_s, 'bold')}")
    usage = result.get("usage", {})
    token_info = (f"输入 {usage.get('prompt_tokens', 0)} + "
                  f"输出 {usage.get('completion_tokens', 0)}"
                  f" = 总计 {usage.get('total_tokens', 0)} ({usage.get('calls', 0)} 次调用)")
    print(f"  Token:  {c(token_info, 'dim')}")

    # --- 最终报告预览 ---
    final = result.get("result", "")
    if final:
        print_header("最终报告")
        # 提取 JSON 块
        if "```json" in final:
            json_start = final.index("```json") + 7
            json_end = final.index("```", json_start) if "```" in final[json_start:] else len(final)
            json_text = final[json_start:json_end].strip()
            try:
                parsed = json.loads(json_text)
                # 漏洞检测
                if "findings" in parsed:
                    findings = parsed["findings"]
                    print(f"  发现 {c(str(len(findings)), 'bold')} 个问题:\n")
                    for i, f in enumerate(findings, 1):
                        sev = f.get("severity", "?")
                        sev_color = "red" if sev == "high" else ("yellow" if sev == "medium" else "green")
                        print(f"  {i}. [{c(sev.upper(), sev_color)}] {c(f.get('title', '?'), 'bold')}")
                        if f.get("cwe_id"):
                            print(f"     CWE: {f['cwe_id']}")
                        if f.get("description"):
                            desc = f["description"][:150]
                            print(f"     {c(desc, 'dim')}")
                        if f.get("fix_suggestion"):
                            fix = f["fix_suggestion"][:120]
                            print(f"     修复: {c(fix, 'green')}")
                # 恶意分析
                elif "verdict" in parsed:
                    v = parsed["verdict"]
                    malicious = v.get("maliciousness", "?")
                    m_color = "red" if malicious == "malicious" else ("yellow" if malicious == "suspicious" else "green")
                    print(f"  判定: {c(malicious.upper(), m_color + ' bold')}")
                    print(f"  置信度: {v.get('confidence', '?')}")
                    print(f"  理由: {c(v.get('reason', '?'), 'dim')}")
                    behaviors = parsed.get("behaviors", [])
                    if behaviors:
                        print(f"\n  识别行为 ({len(behaviors)} 项):")
                        for b in behaviors:
                            print(f"    - [{c(b.get('severity', '?').upper(), 'yellow')}] {b.get('description', '?')}")
                            if b.get("attack_technique"):
                                print(f"      ATT&CK: {b['attack_technique']} ({b.get('attack_tactic', '')})")
                    iocs = parsed.get("iocs", [])
                    if iocs:
                        print(f"\n  IOC 清单 ({len(iocs)} 项):")
                        for ioc in iocs:
                            malicious_mark = c(" MALICIOUS", "red") if ioc.get("threat_intel_result") == "已知恶意" else ""
                            print(f"    - [{ioc.get('type', '?')}] {ioc.get('value', '?')}{malicious_mark}")
            except json.JSONDecodeError:
                print(f"  {c(final[:500], 'dim')}")
        else:
            print(f"  {c(final[:600], 'dim')}")

    print(f"\n{c('━' * 70, 'dim')}")
    print(f"  {c('Demo 2.0 完成', 'green bold')}")
    print(f"{c('━' * 70, 'dim')}\n")


# ==============================================================================
# Main
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="SecAgent Demo 2.0 — AI 安全分析 Agent 命令行工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s --file ../tests/samples/sqli.py
  %(prog)s --code "os.system('rm -rf /')"
  %(prog)s --file suspicious.exe --output report.json
  %(prog)s --file app.py --type vulnerability_detection --verbose
        """,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--file", "-f", help="待分析的文件路径")
    group.add_argument("--code", "-c", help="待分析的代码文本（内联）")
    parser.add_argument("--type", "-t", dest="task_type", choices=["vulnerability_detection", "malware_analysis"],
                       default=None, help="手动指定任务类型（默认自动识别）")
    parser.add_argument("--output", "-o", help="保存 JSON 报告到指定文件")
    parser.add_argument("--max-steps", type=int, default=8, help="最大 ReAct 步数 (默认 8)")
    parser.add_argument("--verbose", "-v", action="store_true", help="显示调试日志")
    parser.add_argument("--quiet", "-q", action="store_true", help="静默模式（只输出最终结果）")
    parser.add_argument("--mock-only", action="store_true", help="仅使用 mock 工具（不依赖外部 API）")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.INFO)

    # --- 读取输入 ---
    if args.file:
        filepath = args.file
        if os.path.exists(filepath):
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                input_content = f.read()
            if not args.quiet:
                print(f"\n{c(' 读取文件: ' + filepath, 'dim')} ({len(input_content)} 字符)")
        else:
            # 可能是路径，交给 Agent 自行处理（恶意文件路径等）
            input_content = filepath
            if not args.quiet:
                print(f"\n{c(' 文件路径（将交由 Agent 处理）: ' + filepath, 'dim')}")
    else:
        input_content = args.code
        if not args.quiet:
            print(f"\n{c(' 内联代码输入', 'dim')} ({len(input_content)} 字符)")

    # --- 初始化引擎 ---
    if not args.quiet:
        print(f"{c(' 初始化 Agent 引擎...', 'dim')}")

    llm = LLMClient(max_tokens=2048, max_input_tokens=8000)
    engine = AgentEngine(llm=llm, max_steps=args.max_steps)

    # --- 加载工具 ---
    real_count = 0
    if not args.mock_only:
        if not args.quiet:
            print(f"{c(' 正在加载真实工具模块...', 'dim')}")
        real_count = _load_real_tools(engine)

    # 补充 mock 工具
    _load_mock_tools(engine, mock_only=args.mock_only)

    if not args.quiet:
        tool_names = list(engine._tool_executors.keys())
        real_labels = [f"{n}{c('*', 'green')}" for n in tool_names
                       if n in ["scan_code", "query_cve", "query_cwe", "query_threat_intel"] and not args.mock_only]
        mock_labels = [n for n in tool_names if n not in ["scan_code", "query_cve", "query_cwe", "query_threat_intel"] or args.mock_only]
        print(f"  工具: 真实 {c(str(real_count), 'green')} 个 | 模拟 {c(str(len(mock_labels)), 'yellow')} 个")
        print(f"  可用: {c(', '.join(tool_names), 'dim')}")

    # --- 步骤回调 ---
    if not args.quiet:
        print_header("Agent 分析过程")
        def on_step(step: dict) -> None:
            print_step(step)
        engine.on_step(on_step)
    else:
        engine.on_step(lambda _: None)

    # --- 执行 ---
    start_time = time.time()
    result = engine.run(task_type=args.task_type, input_content=input_content)

    # --- 输出 ---
    print_verdict(engine, result)

    # --- 保存 JSON ---
    if args.output:
        # 转换为可序列化格式
        serializable = {
            "task_type": result["task_type"],
            "detect_reason": result["detect_reason"],
            "total_steps": result["total_steps"],
            "elapsed_seconds": result["elapsed_seconds"],
            "error": result.get("error"),
            "confidence": result.get("confidence", {}),
            "aggregated": result.get("aggregated", {}),
            "usage": result.get("usage", {}),
            "steps": [
                {"step_num": s.get("step_num"), "type": s["type"], "data": s.get("data", {})}
                for s in result.get("steps", [])
            ],
            "final_report": result.get("result"),
        }
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(serializable, f, ensure_ascii=False, indent=2)
        print(f"  {c('报告已保存: ' + args.output, 'green')}")


if __name__ == "__main__":
    main()
