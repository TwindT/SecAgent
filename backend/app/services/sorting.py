"""
分析结果智能排序模块 — 按危险等级/置信度对安全发现进行排序。

用于报告展示、API 返回结果、前端列表渲染等场景。
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)

# 严重度排序权重（数值越大越严重，排在前面）
SEVERITY_ORDER: dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
    "none": 0,
}

# 置信度排序权重
CONFIDENCE_ORDER: dict[str, int] = {
    "high": 3,
    "medium": 2,
    "low": 1,
}


def _severity_weight(severity: str) -> int:
    """将严重度字符串映射为排序权重。"""
    if not severity:
        return 0
    return SEVERITY_ORDER.get(str(severity).lower().strip(), 0)


def _confidence_weight(confidence) -> int:
    """将置信度映射为排序权重。

    支持字符串 ("high"/"medium"/"low") 和数值 (0.0-1.0)。
    """
    if confidence is None:
        return CONFIDENCE_ORDER["low"]

    if isinstance(confidence, (int, float)):
        if confidence >= 0.8:
            return CONFIDENCE_ORDER["high"]
        elif confidence >= 0.5:
            return CONFIDENCE_ORDER["medium"]
        else:
            return CONFIDENCE_ORDER["low"]

    return CONFIDENCE_ORDER.get(
        str(confidence).lower().strip(),
        CONFIDENCE_ORDER["low"],
    )


def sort_findings(
    findings: list[dict],
    sort_by: Optional[list[str]] = None,
) -> list[dict]:
    """对安全发现列表进行智能排序。

    默认排序优先级：严重度（降序）→ 置信度（降序）

    Parameters
    ----------
    findings : list[dict]
        待排序的发现列表，每项应包含：
        - severity / risk_level : 严重等级
        - confidence : 置信度（可选）
    sort_by : list[str] | None
        排序字段优先级列表，如 ["severity", "confidence"]
        为 None 时使用默认顺序。

    Returns
    -------
    list[dict]
        排序后的新列表（不修改原列表）
    """
    if not findings:
        return []

    if sort_by is None:
        sort_by = ["severity", "confidence"]

    sorted_list = sorted(
        findings,
        key=lambda f: _sort_key(f, sort_by),
        reverse=True,
    )

    return sorted_list


def _sort_key(finding: dict, sort_by: list[str]) -> tuple:
    """生成排序用的多级键值元组。"""
    keys: list = []
    for field in sort_by:
        if field == "severity":
            sev = finding.get("severity", finding.get("risk_level", ""))
            keys.append(_severity_weight(sev))
        elif field == "confidence":
            conf = finding.get("confidence", None)
            keys.append(_confidence_weight(conf))
        elif field == "cvss":
            cvss = finding.get("cvss", 0)
            keys.append(float(cvss) if cvss else 0)
        elif field == "ioc_count":
            # 按 IOC 数量排序（恶意分析用）
            count = finding.get("ioc_count", 0)
            keys.append(int(count) if count else 0)
        else:
            # 通用字段：按字符串/数值比较
            val = finding.get(field, "")
            keys.append(val if val is not None else "")
    return tuple(keys)


def sort_vulnerabilities(findings: list[dict]) -> list[dict]:
    """对漏洞发现列表排序：高危优先 → 置信度高优先。"""
    return sort_findings(findings, sort_by=["severity", "confidence", "cvss"])


def sort_malware_indicators(findings: list[dict]) -> list[dict]:
    """对恶意分析指标列表排序：严重度优先 → IOC 数量多优先。"""
    return sort_findings(findings, sort_by=["severity", "confidence", "ioc_count"])


def rank_tasks_by_risk(tasks: list[dict]) -> list[dict]:
    """按风险等级对任务列表排序：高危任务在前。

    适用于历史任务列表、仪表盘等场景。

    Parameters
    ----------
    tasks : list[dict]
        任务列表，每项应包含 result_json 或 risk_level 字段

    Returns
    -------
    list[dict]
        按风险降序排列的任务列表
    """
    import json

    def _task_risk(task: dict) -> int:
        result = task.get("result_json", "")
        if isinstance(result, str) and result:
            try:
                parsed = json.loads(result)
            except (json.JSONDecodeError, TypeError):
                parsed = {}
        elif isinstance(result, dict):
            parsed = result
        else:
            parsed = {}

        risk = ""
        if isinstance(parsed, dict):
            summary = parsed.get("summary", {})
            if isinstance(summary, dict):
                risk = summary.get("risk_level", "")
            if not risk:
                verdict = parsed.get("verdict", parsed.get("malicious", ""))
                risk = _verdict_to_risk(str(verdict))

        return _severity_weight(risk)

    return sorted(tasks, key=_task_risk, reverse=True)


def _verdict_to_risk(verdict: str) -> str:
    """将恶意判定映射为风险等级。"""
    verdict_lower = verdict.lower()
    if verdict_lower in ("malicious", "恶意"):
        return "high"
    elif verdict_lower in ("suspicious", "可疑"):
        return "medium"
    elif verdict_lower in ("benign", "clean", "安全"):
        return "low"
    return "info"
