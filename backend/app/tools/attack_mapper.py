"""
3.4 ATT&CK 技术映射工具 — 将恶意行为描述映射到 MITRE ATT&CK 框架。

基于本地 ATT&CK Enterprise STIX 数据，通过关键词匹配和评分机制，
将自然语言行为描述映射到对应的战术（Tactic）和技术（Technique）。
提供 map_attack 工具入口函数，统一由 AgentEngine 通过 register_tool() 调用。
"""

import re
import logging

from data.attack_loader import ATTACKLoader

logger = logging.getLogger(__name__)

# 全局单例，延迟加载
_loader: ATTACKLoader | None = None

# 停用词（分词时过滤）
_STOP_WORDS: set[str] = {
    "a", "an", "the", "is", "are", "was", "were", "be", "been", "being",
    "have", "has", "had", "do", "does", "did", "will", "would", "could",
    "should", "may", "might", "can", "shall", "to", "of", "in", "for",
    "on", "with", "at", "by", "from", "as", "into", "through", "during",
    "before", "after", "above", "below", "between", "under", "and", "but",
    "or", "not", "no", "nor", "so", "if", "then", "than", "that", "this",
    "it", "its", "using", "used", "via", "also", "about", "other", "some",
    "any", "all", "each", "every", "very", "just", "only", "such", "which",
}


def _get_loader() -> ATTACKLoader:
    """获取 ATT&CK 数据加载器单例。"""
    global _loader
    if _loader is None:
        _loader = ATTACKLoader()
    return _loader


def _tokenize(text: str) -> list[str]:
    """将行为描述分词，返回有意义的搜索关键词列表。

    返回单个词 + 相邻两词组成的 bigram，用于更精确的短语匹配。
    """
    # 转小写，按非字母数字字符分割
    words = re.split(r"[^a-zA-Z0-9]+", text.lower())
    words = [w.strip() for w in words if w.strip()]

    # 过滤停用词和过短的词
    meaningful = [w for w in words if w not in _STOP_WORDS and len(w) >= 2]

    keywords = list(meaningful)

    # 生成 bigram（相邻两词组合）
    for i in range(len(meaningful) - 1):
        bigram = f"{meaningful[i]} {meaningful[i+1]}"
        keywords.append(bigram)

    return keywords


# ======================================================================
# map_attack — 统一入口（供 Agent Function Calling 调用）
# ======================================================================

def map_attack(behavior: str) -> dict:
    """将恶意行为描述映射到 MITRE ATT&CK 框架的技术和战术。

    这是 Agent map_attack 工具的入口函数，
    签名与 MAP_ATTACK_SCHEMA 一致。

    对输入的行为描述进行分词，通过关键词匹配 ATT&CK 技术库，
    返回按相关度降序排列的匹配结果（最多 10 条）。

    Parameters
    ----------
    behavior : str
        恶意行为描述，如 'credential dumping'、
        'remote file download via URLDownloadToFile'、
        'registry run key persistence'。

    Returns
    -------
    dict
        {"status": "ok", "matches": [...], "total": int, "error": None}
        每条 match 包含：technique_id, technique_name, tactic_id,
        tactic_name, description, score
    """
    if not behavior or not isinstance(behavior, str):
        return {
            "status": "error",
            "matches": [],
            "total": 0,
            "error": "行为描述为空或格式不正确",
        }

    try:
        loader = _get_loader()
        keywords = _tokenize(behavior)

        if not keywords:
            return {
                "status": "error",
                "matches": [],
                "total": 0,
                "error": "无法从描述中提取有效关键词",
            }

        logger.info("ATT&CK 映射: behavior=%r → keywords=%s", behavior[:100], keywords[:10])

        raw_matches = loader.map_attack_by_keywords(keywords)

        # 格式化输出
        matches = []
        for m in raw_matches[:10]:
            tech = m["technique"]
            matches.append({
                "technique_id": tech["id"],
                "technique_name": tech["name"],
                "tactic_id": tech.get("tactic_id", ""),
                "tactic_name": tech.get("tactic_name", ""),
                "description": tech.get("description", ""),
                "score": m["score"],
            })

        return {
            "status": "ok",
            "matches": matches,
            "total": len(matches),
            "error": None,
        }

    except Exception as e:
        logger.exception("map_attack 执行异常")
        return {
            "status": "error",
            "matches": [],
            "total": 0,
            "error": f"ATT&CK 映射失败: {str(e)}",
        }
