"""
AI 报告摘要生成模块 — 调用 LLM 将分析结果凝练为简洁的可读摘要。

用于:
- 报告封面概述
- 仪表盘任务列表简要描述
- 历史记录快速预览
"""

import json
import logging
from typing import Optional

from ..agent.llm import LLMClient

logger = logging.getLogger(__name__)

# 摘要最大 Token 数（生成用）
SUMMARY_MAX_TOKENS = 500

# 输入结果截断长度（避免送入过多原始数据）
MAX_INPUT_CHARS = 6000

# ------------------------------------------------------------------
# Prompt 模板
# ------------------------------------------------------------------

_VULN_SUMMARY_PROMPT = """你是一名资深安全分析专家。请将以下代码漏洞检测结果凝练为一段简洁的摘要（150-300字）。

要求：
1. 用一句话概括整体风险等级
2. 列出最重要的 1-3 个发现（漏洞类型 + 位置 + 严重程度）
3. 给出最重要的 1 条修复建议
4. 使用中文，专业但易懂

只输出摘要文本，不要加标题或格式标记。"""

_MALWARE_SUMMARY_PROMPT = """你是一名资深恶意代码分析专家。请将以下恶意代码分析结果凝练为一段简洁的摘要（150-300字）。

要求：
1. 用一句话给出判定结论（恶意/可疑/安全）及置信度
2. 列出 1-3 个关键恶意行为或可疑特征
3. 如有 IOC，提 1-2 个最关键的
4. 使用中文，专业但易懂

只输出摘要文本，不要加标题或格式标记。"""

# ------------------------------------------------------------------
# 摘要生成器
# ------------------------------------------------------------------


def generate_summary(
    result_json: Optional[str],
    task_type: str,
    llm: Optional[LLMClient] = None,
) -> str:
    """调用 LLM 将分析结果 JSON 凝练为一段可读摘要。

    Parameters
    ----------
    result_json : str | None
        分析结果的 JSON 字符串
    task_type : str
        "vulnerability_detection" 或 "malware_analysis"
    llm : LLMClient | None
        复用 LLM 客户端，为 None 时自动创建

    Returns
    -------
    str
        生成的摘要文本；如果生成失败或无结果则返回 "暂无分析摘要。"
    """
    if not result_json:
        return "暂无分析摘要。"

    # 解析结果
    try:
        result = json.loads(result_json) if isinstance(result_json, str) else result_json
    except (json.JSONDecodeError, TypeError):
        return "暂无分析摘要。"

    if not isinstance(result, dict) or not result:
        return "暂无分析摘要。"

    # 选择 Prompt
    if "vuln" in task_type:
        prompt = _VULN_SUMMARY_PROMPT
    else:
        prompt = _MALWARE_SUMMARY_PROMPT

    # 提取关键信息作为 LLM 输入（控制长度）
    input_text = _build_summary_input(result, task_type)

    messages = [
        {"role": "system", "content": prompt},
        {"role": "user", "content": input_text},
    ]

    # 调用 LLM
    try:
        client = llm or LLMClient(max_tokens=SUMMARY_MAX_TOKENS)
        response = client.chat(messages=messages)
        summary = response.get("content", "")

        if response.get("error"):
            logger.warning("摘要生成 LLM 调用出错: %s", response["error"])
            return _fallback_summary(result, task_type)

        if not summary or len(summary.strip()) < 10:
            return _fallback_summary(result, task_type)

        return summary.strip()

    except Exception as e:
        logger.warning("摘要生成失败: %s", e)
        return _fallback_summary(result, task_type)


def _build_summary_input(result: dict, task_type: str) -> str:
    """从原始分析结果中提取关键信息作为 LLM 摘要输入，并截断。"""
    parts: list[str] = []

    if "vuln" in task_type:
        summary = result.get("summary", {})
        if isinstance(summary, dict):
            risk = summary.get("risk_level", "未知")
            parts.append(f"整体风险等级: {risk}")
            parts.append(f"发现问题数: {summary.get('total_findings', '?')}")

        findings = result.get("findings", result.get("vulnerabilities", []))
        if isinstance(findings, list) and findings:
            parts.append("\n主要发现:")
            for f in findings[:5]:
                if isinstance(f, dict):
                    title = f.get("title", f.get("name", f.get("rule_id", "?")))
                    severity = f.get("severity", "?")
                    loc = f.get("location", f.get("file", ""))
                    desc = str(f.get("description", f.get("message", "")))[:200]
                    parts.append(f"  - [{severity}] {title} @ {loc}: {desc}")

        suggestions = result.get("suggestions", result.get("recommendations", []))
        if isinstance(suggestions, list) and suggestions:
            parts.append("\n修复建议:")
            for s in suggestions[:3]:
                parts.append(f"  - {str(s)[:200]}")
    else:
        verdict = result.get("verdict", result.get("malicious", "未知"))
        confidence = result.get("confidence", "?")
        parts.append(f"判定: {verdict} (置信度: {confidence})")

        behaviors = result.get("behaviors", result.get("behavior", []))
        if isinstance(behaviors, list) and behaviors:
            parts.append("\n关键行为:")
            for b in behaviors[:5]:
                parts.append(f"  - {str(b)[:200]}")

        iocs = result.get("iocs", result.get("ioc", []))
        if isinstance(iocs, list) and iocs:
            parts.append("\nIOC 清单:")
            for ioc in iocs[:5]:
                parts.append(f"  - [{ioc.get('type', '?')}] {ioc.get('value', '?')}")

    text = "\n".join(parts)
    if len(text) > MAX_INPUT_CHARS:
        text = text[:MAX_INPUT_CHARS] + "\n...(内容已截断)"
    return text


def _fallback_summary(result: dict, task_type: str) -> str:
    """LLM 不可用时的规则兜底摘要。"""
    if "vuln" in task_type:
        summary = result.get("summary", {})
        risk = summary.get("risk_level", "未知") if isinstance(summary, dict) else "未知"
        findings = result.get("findings", result.get("vulnerabilities", []))
        count = len(findings) if isinstance(findings, list) else 0

        if count == 0:
            return f"分析完成，未发现明显安全漏洞。整体风险等级: {risk}。"
        high = sum(1 for f in findings if isinstance(f, dict) and str(f.get("severity", "")).lower() == "high")
        return (
            f"共发现 {count} 个潜在安全问题"
            + (f"（其中 {high} 个高危）" if high else "")
            + f"，整体风险等级: {risk}。"
        )
    else:
        verdict = result.get("verdict", result.get("malicious", "未知"))
        confidence = result.get("confidence", "?")
        # 如果 confidence 是 dict，提取 level 字段
        if isinstance(confidence, dict):
            confidence = confidence.get("level", str(confidence))
        behaviors = result.get("behaviors", result.get("behavior", []))
        b_count = len(behaviors) if isinstance(behaviors, list) else 0
        iocs = result.get("iocs", result.get("ioc", []))
        ioc_count = len(iocs) if isinstance(iocs, list) else 0

        return (
            f"分析判定: {verdict}（置信度: {confidence}）。"
            + (f" 检测到 {b_count} 个可疑行为。" if b_count else "")
            + (f" 提取了 {ioc_count} 个 IOC。" if ioc_count else "")
        )
