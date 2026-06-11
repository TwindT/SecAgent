"""
2.6 静态分析工具集成 — semgrep / bandit 代码扫描。

提供 run_semgrep / run_bandit / scan_code 三个工具入口函数，
统一由 AgentEngine 通过 register_tool() 调用。
"""

import os
import json
import tempfile
import subprocess
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------
# 语言 → 文件扩展名 & semgrep lang 映射
# ------------------------------------------------------------------
_LANG_EXT = {
    "python": ".py",
    "java": ".java",
    "javascript": ".js",
    "c": ".c",
}

_SEMGREP_LANG = {
    "python": "python",
    "java": "java",
    "javascript": "javascript",
    "c": "c",
}


def run_semgrep(code: str, language: str = "auto") -> dict:
    """对源代码执行 semgrep 静态安全扫描。

    Parameters
    ----------
    code : str
        待扫描的源代码文本。
    language : str
        编程语言，支持 python / java / javascript / c / auto。

    Returns
    -------
    dict
        {"status": "ok"|"error", "findings": [...], "total": int, "error": str|None}
    """
    ext = _LANG_EXT.get(language, ".txt")

    temp_file: Optional[str] = None
    try:
        # 写入临时文件
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=ext, delete=False, encoding="utf-8"
        ) as f:
            f.write(code)
            temp_file = f.name

        # 执行 semgrep（--config=auto 自动检测语言，不传 --lang）
        cmd = [
            "semgrep",
            "--json",
            "--config=auto",
            temp_file,
        ]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
        )

        # semgrep 即使有 findings 也返回 0；返回非 0 表示执行错误
        if result.returncode != 0:
            logger.error("semgrep 执行失败: %s", result.stderr)
            return {
                "status": "error",
                "findings": [],
                "total": 0,
                "error": result.stderr.strip()[-500:],
            }

        # 解析 JSON 输出
        raw = json.loads(result.stdout) if result.stdout.strip() else {"results": []}
        findings = _normalize_findings(_parse_semgrep_output(raw), source="semgrep")
        return {
            "status": "ok",
            "findings": findings,
            "total": len(findings),
            "error": None,
        }

    except FileNotFoundError:
        return {
            "status": "error",
            "findings": [],
            "total": 0,
            "error": "semgrep 未安装，请先执行 pip install semgrep",
        }
    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "findings": [],
            "total": 0,
            "error": "semgrep 执行超时（60s）",
        }
    except json.JSONDecodeError as e:
        return {
            "status": "error",
            "findings": [],
            "total": 0,
            "error": f"semgrep 输出解析失败: {str(e)}",
        }
    except Exception as e:
        logger.exception("run_semgrep 异常")
        return {
            "status": "error",
            "findings": [],
            "total": 0,
            "error": str(e),
        }
    finally:
        if temp_file and os.path.exists(temp_file):
            os.unlink(temp_file)


# ------------------------------------------------------------------
# semgrep JSON 解析
# ------------------------------------------------------------------
def _parse_semgrep_output(raw: dict) -> list[dict]:
    """将 semgrep 原始 JSON 输出解析为统一的 findings 格式。

    semgrep --json 输出结构:
    {
      "results": [
        {
          "check_id": "python.django.security.audit...",
          "path": "/tmp/xxx.py",
          "start": {"line": 2, "col": 5},
          "end": {"line": 2, "col": 40},
          "extra": {
            "message": "...",
            "severity": "WARNING",
            "lines": "..."
          }
        },
        ...
      ]
    }
    """
    findings: list[dict] = []
    for r in raw.get("results", []):
        findings.append({
            "rule_id": r.get("check_id", "unknown"),
            "severity": r.get("extra", {}).get("severity", "INFO"),
            "file": r.get("path", ""),
            "line": r.get("start", {}).get("line", 0),
            "message": r.get("extra", {}).get("message", ""),
            "code_snippet": r.get("extra", {}).get("lines", "").strip(),
        })
    return findings


# ======================================================================
# 结果标准化
# ======================================================================

# semgrep/bandit 严重度 → 统一严重度
_SEVERITY_MAP = {
    # semgrep
    "ERROR": "HIGH",
    "WARNING": "MEDIUM",
    "INFO": "LOW",
    # bandit
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
}

_SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}


def _normalize_findings(findings: list[dict], source: str) -> list[dict]:
    """标准化扫描结果：统一严重度、清理路径、去重排序。

    标准化后的格式: {rule_id, severity, file, line, message, code_snippet, source}
    """
    seen: set[tuple[str, int]] = set()
    normalized: list[dict] = []

    for f in findings:
        # 统一严重度
        raw_sev = str(f.get("severity", "")).upper()
        severity = _SEVERITY_MAP.get(raw_sev, "INFO")

        entry = {
            "rule_id": f.get("rule_id", "unknown"),
            "severity": severity,
            "file": os.path.basename(f.get("file", "")),
            "line": f.get("line", 0),
            "message": f.get("message", ""),
            "code_snippet": f.get("code_snippet", ""),
            "source": source,
        }

        # 按 (rule_id, line) 去重
        key = (entry["rule_id"], entry["line"])
        if key in seen:
            continue
        seen.add(key)
        normalized.append(entry)

    # 按严重度排序：HIGH → MEDIUM → LOW → INFO
    normalized.sort(key=lambda x: _SEVERITY_ORDER.get(x["severity"], 99))
    return normalized


# ======================================================================
# Bandit — Python 专项安全扫描
# ======================================================================

def run_bandit(code: str) -> dict:
    """对 Python 代码执行 bandit 安全扫描。

    Parameters
    ----------
    code : str
        待扫描的 Python 源代码文本。

    Returns
    -------
    dict
        {"status": "ok"|"error", "findings": [...], "total": int, "error": str|None}
    """
    temp_file: Optional[str] = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        ) as f:
            f.write(code)
            temp_file = f.name

        cmd = ["bandit", "-f", "json", temp_file]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
        )

        if result.returncode not in (0, 1):
            # bandit 返回 1 表示有 findings，0 表示无 findings，其他为错误
            logger.error("bandit 执行失败: %s", result.stderr)
            return {
                "status": "error",
                "findings": [],
                "total": 0,
                "error": result.stderr.strip()[-500:],
            }

        raw = json.loads(result.stdout) if result.stdout.strip() else {"results": []}
        findings = _normalize_findings(_parse_bandit_output(raw), source="bandit")
        return {
            "status": "ok",
            "findings": findings,
            "total": len(findings),
            "error": None,
        }

    except FileNotFoundError:
        return {
            "status": "error",
            "findings": [],
            "total": 0,
            "error": "bandit 未安装，请先执行 pip install bandit",
        }
    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "findings": [],
            "total": 0,
            "error": "bandit 执行超时（60s）",
        }
    except json.JSONDecodeError as e:
        return {
            "status": "error",
            "findings": [],
            "total": 0,
            "error": f"bandit 输出解析失败: {str(e)}",
        }
    except Exception as e:
        logger.exception("run_bandit 异常")
        return {
            "status": "error",
            "findings": [],
            "total": 0,
            "error": str(e),
        }
    finally:
        if temp_file and os.path.exists(temp_file):
            os.unlink(temp_file)


def _parse_bandit_output(raw: dict) -> list[dict]:
    """将 bandit JSON 输出解析为统一的 findings 格式。

    bandit -f json 输出结构:
    {
      "results": [
        {
          "test_id": "B308",
          "test_name": "hardcoded_tmp_directory",
          "issue_severity": "MEDIUM",
          "issue_confidence": "HIGH",
          "issue_text": "Use of mark_safe() ...",
          "filename": "/tmp/xxx.py",
          "line_number": 5,
          "code": "..."
        }
      ]
    }
    """
    findings: list[dict] = []
    for r in raw.get("results", []):
        findings.append({
            "rule_id": "{} - {}".format(r.get("test_id", ""), r.get("test_name", "")),
            "severity": r.get("issue_severity", "INFO"),
            "file": r.get("filename", ""),
            "line": r.get("line_number", 0),
            "message": r.get("issue_text", ""),
            "code_snippet": (r.get("code") or "").strip(),
        })
    return findings


# ======================================================================
# scan_code — 统一入口（供 Agent Function Calling 调用）
# ======================================================================

def scan_code(code: str, language: str = "auto") -> dict:
    """对源代码进行安全扫描，根据语言分发到 semgrep/bandit。

    这是 Agent scan_code 工具的入口函数，签名与 SCAN_CODE_SCHEMA 一致。

    Parameters
    ----------
    code : str
        待扫描的源代码文本。
    language : str
        编程语言（python / java / javascript / c / auto）。

    Returns
    -------
    dict
        {
            "status": "ok"|"error",
            "findings": [...],
            "total": int,
            "scanners": ["semgrep", ...],
            "error": str|None
        }
    """
    all_findings: list[dict] = []
    scanners_used: list[str] = []
    errors: list[str] = []

    # 1. semgrep（所有语言通用）
    sg = run_semgrep(code, language=language)
    if sg["status"] == "ok":
        all_findings.extend(sg["findings"])
        scanners_used.append("semgrep")
    else:
        errors.append(f"semgrep: {sg.get('error', 'unknown')}")

    # 2. bandit（仅 Python）
    if language in ("python", "auto"):
        bd = run_bandit(code)
        if bd["status"] == "ok":
            # 与 semgrep 结果合并去重
            existing = {(f["rule_id"], f["line"]) for f in all_findings}
            for f in bd["findings"]:
                if (f["rule_id"], f["line"]) not in existing:
                    all_findings.append(f)
                    existing.add((f["rule_id"], f["line"]))
            scanners_used.append("bandit")
        else:
            errors.append(f"bandit: {bd.get('error', 'unknown')}")

    # 3. 排序
    all_findings.sort(key=lambda x: _SEVERITY_ORDER.get(x["severity"], 99))

    if not scanners_used:
        return {
            "status": "error",
            "findings": [],
            "total": 0,
            "scanners": [],
            "error": "; ".join(errors),
        }

    return {
        "status": "ok",
        "findings": all_findings,
        "total": len(all_findings),
        "scanners": scanners_used,
        "error": None,
    }
