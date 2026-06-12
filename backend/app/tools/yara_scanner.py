"""
3.5 YARA 规则扫描工具 — 使用 YARA 规则对文件进行恶意软件特征匹配。

编译 data/yara_rules/ 下的所有 YARA 规则，
对指定文件执行扫描，返回匹配到的规则及其元信息。
提供 scan_yara 工具入口函数，统一由 AgentEngine 通过 register_tool() 调用。
"""

import os
import logging
from pathlib import Path
from typing import Optional

import yara

logger = logging.getLogger(__name__)

# 规则目录（相对于本文件 — 位于 backend/app/tools/）
_RULES_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "yara_rules"

# 编译后的规则缓存（None 表示尚未加载，加载失败也缓存为 None）
_compiled_rules: Optional[yara.Rules] = None
# 已编译规则的文件数量
_compiled_rule_count: int = 0


def _get_rules() -> Optional[yara.Rules]:
    """获取编译后的 YARA 规则（延迟加载 + 缓存）。

    首次调用时编译全部 .yar 文件，后续直接返回缓存。
    """
    global _compiled_rules, _compiled_rule_count
    if _compiled_rules is not None:
        return _compiled_rules

    yar_files = sorted(_RULES_DIR.glob("*.yar"))
    if not yar_files:
        logger.warning("YARA 规则目录为空: %s", _RULES_DIR)
        return None

    try:
        filepaths = {f"file_{i}": str(f) for i, f in enumerate(yar_files)}
        _compiled_rules = yara.compile(filepaths=filepaths)
        _compiled_rule_count = len(yar_files)
        logger.info("已加载 %d 个 YARA 规则文件", _compiled_rule_count)
    except yara.Error as e:
        logger.error("YARA 规则编译失败: %s", e)
        _compiled_rules = None  # 缓存 None 避免重复尝试
        _compiled_rule_count = 0
    except Exception as e:
        logger.exception("YARA 规则加载异常")
        _compiled_rules = None
        _compiled_rule_count = 0

    return _compiled_rules


# ======================================================================
# scan_yara — 统一入口（供 Agent Function Calling 调用）
# ======================================================================

def scan_yara(file_path: str) -> dict:
    """使用 YARA 规则扫描指定文件，检测是否匹配已知恶意软件特征。

    这是 Agent scan_yara 工具的入口函数，
    签名与 SCAN_YARA_SCHEMA 一致。

    Parameters
    ----------
    file_path : str
        待扫描文件的本地路径。

    Returns
    -------
    dict
        {"status": "ok"|"error", "matched": bool, "matches": [...],
         "rules_loaded": int|None, "error": str|None}
        每条 match 包含：rule_name, category, severity, description, tags, meta
    """
    if not file_path or not isinstance(file_path, str):
        return {
            "status": "error",
            "matched": False,
            "matches": [],
            "rules_loaded": None,
            "error": "文件路径为空或格式不正确",
        }

    file = Path(file_path)
    if not file.exists():
        return {
            "status": "error",
            "matched": False,
            "matches": [],
            "rules_loaded": None,
            "error": f"文件不存在: {file_path}",
        }
    if not file.is_file():
        return {
            "status": "error",
            "matched": False,
            "matches": [],
            "rules_loaded": None,
            "error": f"路径不是文件: {file_path}",
        }

    try:
        rules = _get_rules()
        if rules is None:
            return {
                "status": "error",
                "matched": False,
                "matches": [],
                "rules_loaded": None,
                "error": "YARA 规则未加载或编译失败",
            }

        yara_matches = rules.match(str(file.resolve()), timeout=60)

        matches = []
        for m in yara_matches:
            meta = m.meta or {}
            # 提取命中的字符串（去重、仅前 10 条）
            strings = list(dict.fromkeys(
                [str(s.instances[0]) if s.instances else str(s.identifier)
                 for s in m.strings]
            ))[:10]

            matches.append({
                "rule_name": m.rule,
                "namespace": m.namespace,
                "category": meta.get("category", ""),
                "severity": meta.get("severity", ""),
                "description": meta.get("description", ""),
                "author": meta.get("author", ""),
                "matched_strings": strings,
            })

        return {
            "status": "ok",
            "matched": len(matches) > 0,
            "matches": matches,
            "rules_loaded": _compiled_rule_count,
            "error": None,
        }

    except yara.TimeoutError:
        return {
            "status": "error",
            "matched": False,
            "matches": [],
            "rules_loaded": None,
            "error": "YARA 扫描超时（60s）",
        }
    except yara.Error as e:
        logger.error("YARA 扫描错误: %s", e)
        return {
            "status": "error",
            "matched": False,
            "matches": [],
            "rules_loaded": None,
            "error": f"YARA 扫描失败: {str(e)}",
        }
    except Exception as e:
        logger.exception("scan_yara 执行异常")
        return {
            "status": "error",
            "matched": False,
            "matches": [],
            "rules_loaded": None,
            "error": f"YARA 扫描异常: {str(e)}",
        }
