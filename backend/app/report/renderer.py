"""报告渲染引擎 — 将分析结果 JSON 填入 Markdown 模板"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ..services.summarizer import generate_summary
from ..services.sorting import sort_findings

logger = logging.getLogger(__name__)

TEMPLATES_DIR = Path(__file__).parent / "templates"


def _fmt_confidence(conf) -> str:
    """将置信度（可能是 dict 或字符串）统一转为可读字符串。"""
    if isinstance(conf, dict):
        level = conf.get("level", "?")
        score = conf.get("score", conf.get("max_score", ""))
        if score:
            return f"{level} ({score}/100)"
        return str(level)
    return str(conf) if conf else "-"

# 漏洞检测默认评分（后续由 Agent 实际填充）
DEFAULT_SCORES = {
    "score_quality": "-",
    "score_auth": "-",
    "score_authz": "-",
    "score_data": "-",
    "score_crypto": "-",
    "score_logging": "-",
    "note_quality": "待分析",
    "note_auth": "待分析",
    "note_authz": "待分析",
    "note_data": "待分析",
    "note_crypto": "待分析",
    "note_logging": "待分析",
}


def _load_template(name: str) -> str:
    """加载 Markdown 模板文件。"""
    path = TEMPLATES_DIR / name
    if not path.exists():
        raise FileNotFoundError(f"模板文件不存在: {path}")
    return path.read_text(encoding="utf-8")


def _parse_result(result_json: str | None) -> dict:
    """将 result_json 字符串解析为 dict，兼容多种格式。"""
    if not result_json:
        return {}
    try:
        return json.loads(result_json)
    except (json.JSONDecodeError, TypeError):
        try:
            import ast
            return ast.literal_eval(result_json)
        except (ValueError, SyntaxError):
            return {"raw": result_json}


def _fmt_table(headers: list[str], rows: list[list[str]]) -> str:
    """生成 Markdown 表格字符串。"""
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join(["------" for _ in headers]) + "|"]
    for row in rows:
        lines.append("| " + " | ".join(str(c) for c in row) + " |")
    return "\n".join(lines)


def _build_vuln_context(task, result: dict) -> dict:
    """构建漏洞检测报告的模板上下文。"""
    summary_data = result.get("summary", {})
    findings = result.get("findings", result.get("vulnerabilities", []))
    # 智能排序：高危 → 中危 → 低危，同等级按置信度降序
    if isinstance(findings, list) and findings:
        findings = sort_findings(findings)
    suggestions = result.get("suggestions", result.get("recommendations", []))

    # 风险等级映射
    risk_map = {"high": "🔴 高危", "medium": "🟡 中危", "low": "🟢 低危", "info": "ℹ️ 信息"}
    risk_level = risk_map.get(str(summary_data.get("risk_level", "")).lower(), str(summary_data.get("risk_level", "-")))

    # 构建发现列表
    findings_md = "未发现明显漏洞。" if not isinstance(findings, list) or not findings else ""
    for i, v in enumerate(findings or [], 1):
        if isinstance(v, dict):
            sev = str(v.get("severity", "-")).upper()
            title = v.get("title", v.get("name", f"问题 {i}"))
            desc = v.get("description", v.get("detail", ""))
            cwe = v.get("cwe_id", v.get("cwe", ""))
            location = v.get("location", v.get("file", ""))
            line = v.get("line", "")

            findings_md += f"\n### {i}. {title}\n\n"
            findings_md += f"- **严重等级**: {sev}\n"
            if cwe:
                findings_md += f"- **CWE 编号**: [{cwe}](https://cwe.mitre.org/data/definitions/{str(cwe).replace('CWE-', '')}.html)\n"
            if location:
                loc_str = f"{location}" + (f":{line}" if line else "")
                findings_md += f"- **位置**: `{loc_str}`\n"
            if desc:
                findings_md += f"\n{desc}\n"
            findings_md += "\n---\n"

    # 构建修复建议
    sug_md = "暂无修复建议。" if not isinstance(suggestions, list) or not suggestions else ""
    for i, s in enumerate(suggestions or [], 1):
        if isinstance(s, dict):
            sug_md += f"\n### {i}. {s.get('title', f'建议 {i}')}\n\n"
            sug_md += f"{s.get('description', s.get('detail', ''))}\n"
            if s.get("code_example"):
                sug_md += f"\n```\n{s['code_example']}\n```\n"
        elif isinstance(s, str):
            sug_md += f"\n{i}. {s}\n"

    # 参考链接
    refs = result.get("references", [])
    ref_md = "暂无参考链接。" if not refs else ""
    for r in (refs or []):
        if isinstance(r, dict):
            ref_md += f"- [{r.get('title', r.get('name', '链接'))}]({r.get('url', '#')})\n"
        elif isinstance(r, str):
            ref_md += f"- {r}\n"

    ctx = {
        "task_id": str(task.id),
        "task_status": str(getattr(task.status, "value", task.status)),
        "language": summary_data.get("language", "-"),
        "created_at": task.created_at.strftime("%Y-%m-%d %H:%M:%S") if task.created_at else "-",
        "elapsed": f"{result.get('elapsed_seconds', '-')} 秒",
        "risk_level": risk_level,
        "confidence": _fmt_confidence(summary_data.get("confidence", result.get("confidence", "-"))),
        "summary": _get_ai_summary(task, result),
        "findings": findings_md,
        "suggestions": sug_md,
        "references": ref_md,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        **DEFAULT_SCORES,
    }
    return ctx


def _build_malware_context(task, result: dict) -> dict:
    """构建恶意代码分析报告的模板上下文。"""
    summary_data = result.get("summary", {})
    behaviors = result.get("behaviors", result.get("behavior", []))
    iocs = result.get("iocs", result.get("ioc", []))
    attack_mapping = result.get("attack_mapping", result.get("attack_techniques", []))
    threat_intel = result.get("threat_intel", result.get("intel_results", []))
    file_info = result.get("file_info", result.get("file_features", {}))

    # 判定映射
    verdict_raw = str(result.get("verdict", result.get("malicious", summary_data.get("verdict", "未知"))))
    verdict_map = {"malicious": "🔴 恶意", "suspicious": "🟡 可疑", "benign": "🟢 安全", "clean": "🟢 安全"}
    verdict = verdict_map.get(verdict_raw.lower(), verdict_raw)

    malicious_map = {"malicious": "高危", "suspicious": "中危", "benign": "无威胁", "clean": "无威胁", "未知": "待确认"}
    malicious_level = malicious_map.get(verdict_raw.lower(), str(verdict_raw))

    # 行为列表
    behavior_md = "未检测到明显恶意行为。" if not isinstance(behaviors, list) or not behaviors else ""
    for b in (behaviors or []):
        if isinstance(b, dict):
            behavior_md += f"\n- **{b.get('name', b.get('behavior', ''))}**: {b.get('description', '')}"
        elif isinstance(b, str):
            behavior_md += f"\n- {b}"

    # ATT&CK 映射
    attack_md = "未匹配到 ATT&CK 技术。" if not isinstance(attack_mapping, list) or not attack_mapping else ""
    for t in (attack_mapping or []):
        if isinstance(t, dict):
            tech_id = t.get("technique_id", t.get("id", ""))
            tech_name = t.get("technique_name", t.get("name", ""))
            tactic = t.get("tactic", "")
            attack_md += f"\n- **{tech_id}** — {tech_name}"
            if tactic:
                attack_md += f"（战术: {tactic}）"

    # IOC 表格
    ioc_headers = ["类型", "值", "说明"]
    ioc_rows = []
    if isinstance(iocs, list):
        for ioc in iocs:
            if isinstance(ioc, dict):
                ioc_rows.append([
                    ioc.get("type", "-"),
                    f"`{ioc.get('value', '-')}`",
                    ioc.get("description", ioc.get("context", "-")),
                ])
    ioc_table = _fmt_table(ioc_headers, ioc_rows) if ioc_rows else "未提取到 IOC。"

    # 威胁情报
    intel_md = "暂无威胁情报查询结果。" if not isinstance(threat_intel, list) or not threat_intel else ""
    for ti in (threat_intel or []):
        if isinstance(ti, dict):
            intel_md += f"\n- **{ti.get('indicator', '')}**: {ti.get('result', ti.get('status', ''))}"
        elif isinstance(ti, str):
            intel_md += f"\n- {ti}"

    # 可疑导入/字符串处理
    suspicious_imports = file_info.get("suspicious_imports", file_info.get("imports", []))
    suspicious_strings = file_info.get("suspicious_strings", file_info.get("strings", []))

    imp_str = ", ".join(f"`{x}`" for x in suspicious_imports[:10]) if isinstance(suspicious_imports, list) and suspicious_imports else "-"
    str_str = ", ".join(f"`{x[:60]}`" for x in suspicious_strings[:5]) if isinstance(suspicious_strings, list) and suspicious_strings else "-"

    if isinstance(suspicious_strings, list) and len(suspicious_strings) > 5:
        str_str += f" ... 等 {len(suspicious_strings)} 项"

    ctx = {
        "task_id": str(task.id),
        "task_status": str(getattr(task.status, "value", task.status)),
        "file_name": file_info.get("file_name", task.input_path or "-"),
        "file_type": file_info.get("file_type", file_info.get("type", "-")),
        "file_size": f"{file_info.get('file_size', file_info.get('size', '-'))}",
        "file_hash": f"`{file_info.get('sha256', file_info.get('hash', '-'))}`",
        "created_at": task.created_at.strftime("%Y-%m-%d %H:%M:%S") if task.created_at else "-",
        "elapsed": f"{result.get('elapsed_seconds', '-')} 秒",
        "verdict": verdict,
        "confidence": _fmt_confidence(result.get("confidence", summary_data.get("confidence", "-"))),
        "malicious_level": malicious_level,
        "summary": _get_ai_summary(task, result),
        "behaviors": behavior_md,
        "attack_mapping": attack_md,
        "ioc_table": ioc_table,
        "pe_timestamp": file_info.get("compile_timestamp", file_info.get("timestamp", "-")),
        "suspicious_imports": imp_str,
        "suspicious_strings": str_str,
        "obfuscation": str(file_info.get("obfuscation", file_info.get("entropy", "-"))),
        "threat_intel": intel_md,
        "remediation": result.get("remediation", result.get("recommendations", "暂无清除建议。")),
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    }
    return ctx


def _get_ai_summary(task, result: dict) -> str:
    """获取 AI 生成的摘要，失败时回退到规则提取。

    将 result_json 原样传给 summarizer，由其内部提取关键字段。
    """
    task_type = getattr(task.type, "value", str(task.type)) or ""

    try:
        summary = generate_summary(
            result_json=task.result_json,
            task_type=task_type,
        )
        if summary and summary != "暂无分析摘要。":
            return summary
    except Exception as e:
        logger.warning("AI 摘要生成失败，使用 fallback: %s", e)

    # fallback：从 result dict 直接提取
    summary_data = result.get("summary", {}) if isinstance(result, dict) else {}
    return str(
        summary_data.get("overview", summary_data.get("description", "暂无分析摘要。"))
        if isinstance(summary_data, dict)
        else "暂无分析摘要。"
    )


def render_markdown(task) -> str:
    """根据任务的分析结果渲染 Markdown 报告。

    参数:
        task: SQLAlchemy Task ORM 对象

    返回:
        str: 完整的 Markdown 格式报告文本
    """
    result = _parse_result(task.result_json)
    task_type = getattr(task.type, "value", str(task.type)) or ""

    if "vuln" in task_type:
        template = _load_template("vuln_report.md")
        ctx = _build_vuln_context(task, result)
    else:
        template = _load_template("malware_report.md")
        ctx = _build_malware_context(task, result)

    return template.format(**ctx)
