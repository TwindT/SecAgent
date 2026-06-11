"""
2.7 漏洞库查询工具 — NVD CVE 查询 + CWE 本地查询。

提供 query_cve / query_cwe 工具入口函数，
统一由 AgentEngine 通过 register_tool() 调用。
"""

import os
import json
import logging
from pathlib import Path
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------
# 配置
# ------------------------------------------------------------------
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CWE_DATA_PATH = Path(__file__).parent.parent.parent / "data" / "cwe.json"

# ------------------------------------------------------------------
# CWE 本地查询（内存缓存）
# ------------------------------------------------------------------
_cwe_cache: Optional[dict] = None


def _load_cwe_data() -> dict:
    """加载 CWE JSON 数据（首次调用后缓存）。"""
    global _cwe_cache
    if _cwe_cache is not None:
        return _cwe_cache
    try:
        with open(CWE_DATA_PATH, "r", encoding="utf-8") as f:
            _cwe_cache = json.load(f)
    except Exception as e:
        logger.error("加载 CWE 数据失败: %s", e)
        _cwe_cache = {"cwes": []}
    return _cwe_cache


def query_cwe(cwe_id: str) -> dict:
    """查询 MITRE CWE 弱点分类库，返回详情。

    Parameters
    ----------
    cwe_id : str
        CWE 编号，如 'CWE-89'。

    Returns
    -------
    dict
        {"status": "ok"|"not_found"|"error", "data": {...}, "error": str|None}
    """
    data = _load_cwe_data()
    cwes = data.get("cwes", [])

    cwe_id_upper = cwe_id.upper()
    for cwe in cwes:
        if cwe.get("id", "").upper() == cwe_id_upper:
            return {
                "status": "ok",
                "data": {
                    "id": cwe.get("id", ""),
                    "name": cwe.get("name", ""),
                    "description": cwe.get("description", ""),
                    "severity": cwe.get("severity", ""),
                    "mitigation": cwe.get("mitigation", ""),
                },
                "error": None,
            }

    return {
        "status": "not_found",
        "data": None,
        "error": f"未找到 {cwe_id}",
    }


# ------------------------------------------------------------------
# NVD CVE 查询
# ------------------------------------------------------------------
def _nvd_headers() -> dict:
    """构建 NVD API 请求头（延迟读取 API Key）。"""
    headers = {"User-Agent": "SecAgent/1.0"}
    api_key = os.getenv("NVD_API_KEY", "")
    if api_key:
        headers["apiKey"] = api_key
    return headers


def _parse_nvd_cve_item(item: dict) -> dict:
    """将 NVD API 返回的单条 CVE 数据提取为简要格式。"""
    cve = item.get("cve", {})
    cve_id = cve.get("id", "")

    # 描述（取英文）
    descriptions = cve.get("descriptions", [])
    desc_text = ""
    for d in descriptions:
        if d.get("lang") == "en":
            desc_text = d.get("value", "")
            break

    # CVSS 评分
    metrics = cve.get("metrics", {})
    cvss_v31 = None
    cvss_v31_data = metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV30", [])
    if cvss_v31_data:
        cvss = cvss_v31_data[0].get("cvssData", {})
        cvss_v31 = {
            "version": cvss.get("version", ""),
            "vectorString": cvss.get("vectorString", ""),
            "baseScore": cvss.get("baseScore", 0),
            "baseSeverity": cvss.get("baseSeverity", ""),
            "attackVector": cvss.get("attackVector", ""),
            "attackComplexity": cvss.get("attackComplexity", ""),
        }

    # CWE 关联
    weaknesses = cve.get("weaknesses", [])
    cwe_ids = []
    for w in weaknesses:
        for wd in w.get("description", []):
            if wd.get("lang") == "en" and wd.get("value"):
                cwe_ids.append(wd["value"])

    # 发布日期
    published = cve.get("published", "")

    return {
        "id": cve_id,
        "description": desc_text[:500] if desc_text else "",
        "cvss": cvss_v31,
        "cwe_ids": cwe_ids,
        "published": published[:10] if published else "",
    }


def query_cve_by_id(cve_id: str) -> dict:
    """通过 CVE 编号查询 NVD 漏洞详情。

    Parameters
    ----------
    cve_id : str
        CVE 编号，如 'CVE-2021-44228'。

    Returns
    -------
    dict
        {"status": "ok"|"not_found"|"error", "data": {...}|None, "error": str|None}
    """
    try:
        resp = httpx.get(
            NVD_BASE_URL,
            params={"cveId": cve_id.upper()},
            headers=_nvd_headers(),
            timeout=30,
        )
        resp.raise_for_status()
        body = resp.json()

        vulns = body.get("vulnerabilities", [])
        if not vulns:
            return {
                "status": "not_found",
                "data": None,
                "error": f"未找到 {cve_id}",
            }

        cve_data = _parse_nvd_cve_item(vulns[0])
        return {
            "status": "ok",
            "data": cve_data,
            "error": None,
        }

    except httpx.HTTPStatusError as e:
        logger.error("NVD API HTTP %d: %s", e.response.status_code, e)
        return {
            "status": "error",
            "data": None,
            "error": f"NVD API 返回 {e.response.status_code}",
        }
    except httpx.RequestError as e:
        logger.error("NVD API 网络错误: %s", e)
        return {
            "status": "error",
            "data": None,
            "error": f"NVD API 连接失败: {str(e)[:200]}",
        }
    except Exception as e:
        logger.exception("query_cve_by_id 异常")
        return {"status": "error", "data": None, "error": str(e)}


def query_cve_by_keyword(keyword: str, limit: int = 10) -> dict:
    """按关键字搜索 NVD CVE 漏洞。

    Parameters
    ----------
    keyword : str
        搜索关键字，如 'SQL injection flask'。
    limit : int
        返回结果数量上限。

    Returns
    -------
    dict
        {"status": "ok"|"error", "data": [...], "total": int, "error": str|None}
    """
    try:
        resp = httpx.get(
            NVD_BASE_URL,
            params={"keywordSearch": keyword, "resultsPerPage": min(limit, 20)},
            headers=_nvd_headers(),
            timeout=30,
        )
        resp.raise_for_status()
        body = resp.json()

        vulns = body.get("vulnerabilities", [])
        results = [_parse_nvd_cve_item(v) for v in vulns[:limit]]

        return {
            "status": "ok",
            "data": results,
            "total": len(results),
            "error": None,
        }

    except httpx.HTTPStatusError as e:
        logger.error("NVD API HTTP %d: %s", e.response.status_code, e)
        return {
            "status": "error",
            "data": [],
            "total": 0,
            "error": f"NVD API 返回 {e.response.status_code}",
        }
    except httpx.RequestError as e:
        logger.error("NVD API 网络错误: %s", e)
        return {
            "status": "error",
            "data": [],
            "total": 0,
            "error": f"NVD API 连接失败: {str(e)[:200]}",
        }
    except Exception as e:
        logger.exception("query_cve_by_keyword 异常")
        return {"status": "error", "data": [], "total": 0, "error": str(e)}


# ======================================================================
# query_cve — 统一入口（供 Agent Function Calling 调用）
# ======================================================================

def query_cve(cve_id: Optional[str] = None, keyword: Optional[str] = None) -> dict:
    """查询 NVD CVE 漏洞数据库。

    这是 Agent query_cve 工具的入口函数，签名与 QUERY_CVE_SCHEMA 一致。
    支持按 CVE ID 精确查询或按关键字搜索（二者选一，cve_id 优先）。

    Parameters
    ----------
    cve_id : str | None
        CVE 编号。
    keyword : str | None
        搜索关键字。

    Returns
    -------
    dict
    """
    if cve_id:
        return query_cve_by_id(cve_id)
    if keyword:
        return query_cve_by_keyword(keyword)
    return {
        "status": "error",
        "data": None,
        "total": 0,
        "error": "请提供 cve_id 或 keyword 参数",
    }
