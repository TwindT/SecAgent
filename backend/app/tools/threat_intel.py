"""
2.8 威胁情报查询工具 — AlienVault OTX + URLhaus。

提供 query_threat_intel 工具入口函数，
统一由 AgentEngine 通过 register_tool() 调用。
"""

import os
import re
import logging
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------
# 配置
# ------------------------------------------------------------------
OTX_BASE_URL = "https://otx.alienvault.com/api/v1/indicators"
URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1/url/"


def _otx_headers() -> dict:
    api_key = os.getenv("OTX_API_KEY", "")
    headers = {"User-Agent": "SecAgent/1.0"}
    if api_key:
        headers["X-OTX-API-KEY"] = api_key
    return headers


# ------------------------------------------------------------------
# IOC 类型自动检测
# ------------------------------------------------------------------
# indicator_type → ioc_type 映射（统一到 schema enum 值）
_OTX_TYPE_MAP = {"IPv4": "ip", "domain": "domain", "file": "hash"}

_IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_HASH_MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
_HASH_SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
_HASH_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")


def _detect_ioc_type(value: str) -> Optional[str]:
    """根据值的格式自动判断 IOC 类型。"""
    if _IPV4_RE.match(value):
        return "ip"
    if _HASH_SHA256_RE.match(value) or _HASH_SHA1_RE.match(value) or _HASH_MD5_RE.match(value):
        return "hash"
    if value.startswith("http://") or value.startswith("https://"):
        return "url"
    # 域名：包含点、不含 @（排除邮箱）、不含空格
    if "." in value and "@" not in value and " " not in value:
        return "domain"
    return None


# ------------------------------------------------------------------
# OTX 通用请求
# ------------------------------------------------------------------
def _query_otx(indicator_type: str, value: str) -> dict:
    """向 AlienVault OTX 查询单个 indicator 的 general 信息。

    indicator_type: "IPv4" | "domain" | "file"
    """
    url = f"{OTX_BASE_URL}/{indicator_type}/{value}/general"
    try:
        resp = httpx.get(url, headers=_otx_headers(), timeout=30)
        resp.raise_for_status()
        body = resp.json()

        pulse_info = body.get("pulse_info", {})
        pulse_count = pulse_info.get("count", 0)

        # 提取前 3 条 pulse 摘要
        pulses = pulse_info.get("pulses", [])
        top_pulses = []
        for p in pulses[:3]:
            top_pulses.append({
                "id": p.get("id", ""),
                "name": p.get("name", ""),
                "description": (p.get("description", "") or "")[:200],
                "created": p.get("created", ""),
                "tags": p.get("tags", [])[:10],
            })

        return {
            "status": "ok",
            "ioc_type": _OTX_TYPE_MAP.get(indicator_type, indicator_type.lower()),
            "ioc_value": value,
            "malicious": pulse_count > 0,
            "pulse_count": pulse_count,
            "top_pulses": top_pulses,
            "validation": body.get("validation", []),
            "error": None,
        }

    except httpx.HTTPStatusError as e:
        logger.error("OTX API HTTP %d: %s", e.response.status_code, e)
        return _degraded_result(_OTX_TYPE_MAP.get(indicator_type, indicator_type.lower()), value, f"OTX API 返回 {e.response.status_code}")
    except httpx.RequestError as e:
        logger.error("OTX API 网络错误: %s", e)
        return _degraded_result(_OTX_TYPE_MAP.get(indicator_type, indicator_type.lower()), value, f"OTX API 连接失败: {str(e)[:200]}")
    except Exception as e:
        logger.exception("_query_otx 异常")
        return _degraded_result(_OTX_TYPE_MAP.get(indicator_type, indicator_type.lower()), value, str(e))


# ------------------------------------------------------------------
# OTX 具体类型查询
# ------------------------------------------------------------------
def query_otx_ip(ip: str) -> dict:
    """查询 AlienVault OTX：检查 IPv4 地址是否已知恶意。

    >>> query_otx_ip("8.8.8.8")
    {"status": "ok", "ioc_type": "ip", "ioc_value": "8.8.8.8", "malicious": False, ...}
    """
    return _query_otx("IPv4", ip)


def query_otx_domain(domain: str) -> dict:
    """查询 AlienVault OTX：检查域名是否已知恶意。"""
    return _query_otx("domain", domain)


def query_otx_hash(file_hash: str) -> dict:
    """查询 AlienVault OTX：检查文件 Hash 是否已知恶意。

    支持 MD5 / SHA1 / SHA256。
    """
    return _query_otx("file", file_hash)


# ------------------------------------------------------------------
# URLhaus 查询
# ------------------------------------------------------------------
def query_urlhaus(url: str) -> dict:
    """查询 URLhaus 恶意 URL 数据库。

    返回该 URL 是否被 URLhaus 收录、恶意标签、威胁类型等信息。
    """
    try:
        resp = httpx.post(
            URLHAUS_API_URL,
            data={"url": url},
            timeout=30,
        )
        resp.raise_for_status()
        body = resp.json()

        query_status = body.get("query_status", "unknown")

        if query_status == "no_results":
            return {
                "status": "ok",
                "ioc_type": "url",
                "ioc_value": url,
                "malicious": False,
                "url_status": "not_found",
                "tags": [],
                "source": "URLhaus",
                "error": None,
            }

        return {
            "status": "ok",
            "ioc_type": "url",
            "ioc_value": url,
            "malicious": query_status == "ok",
            "url_status": body.get("url_status", "unknown"),
            "url_id": body.get("url_id", ""),
            "host": body.get("host", ""),
            "tags": body.get("tags", []),
            "threat": body.get("threat", ""),
            "urlhaus_reference": body.get("urlhaus_reference", ""),
            "first_seen": body.get("firstseen", ""),
            "source": "URLhaus",
            "error": None,
        }

    except httpx.HTTPStatusError as e:
        logger.error("URLhaus API HTTP %d: %s", e.response.status_code, e)
        return _degraded_result("url", url, f"URLhaus API 返回 {e.response.status_code}")
    except httpx.RequestError as e:
        logger.error("URLhaus API 网络错误: %s", e)
        return _degraded_result("url", url, f"URLhaus API 连接失败: {str(e)[:200]}")
    except Exception as e:
        logger.exception("query_urlhaus 异常")
        return _degraded_result("url", url, str(e))


# ------------------------------------------------------------------
# 降级处理
# ------------------------------------------------------------------
def _degraded_result(ioc_type: str, ioc_value: str, reason: str) -> dict:
    """API 调用失败时的降级返回：提示查询失败，建议人工分析。"""
    return {
        "status": "error",
        "ioc_type": ioc_type,
        "ioc_value": ioc_value,
        "malicious": None,
        "pulse_count": 0,
        "top_pulses": [],
        "tags": [],
        "source": None,
        "error": f"威胁情报查询失败，建议人工核实。原因: {reason}",
    }


# ======================================================================
# query_threat_intel — 统一入口（供 Agent Function Calling 调用）
# ======================================================================

def query_threat_intel(ioc_type: str, ioc_value: str) -> dict:
    """查询威胁情报平台，检查 IOC 是否已知恶意。

    这是 Agent query_threat_intel 工具的入口函数，
    签名与 QUERY_THREAT_INTEL_SCHEMA 一致。

    根据 IOC 类型自动分发到：
    - ip     → AlienVault OTX IPv4 查询
    - domain → AlienVault OTX 域名查询
    - url    → URLhaus URL 查询
    - hash   → AlienVault OTX 文件 Hash 查询

    Parameters
    ----------
    ioc_type : str
        IOC 类型：'ip' | 'domain' | 'url' | 'hash'
    ioc_value : str
        IOC 具体值。

    Returns
    -------
    dict
        {"status": "ok"|"error", "ioc_type": ..., "ioc_value": ...,
         "malicious": bool|None, ..., "error": str|None}
    """
    dispatch = {
        "ip": query_otx_ip,
        "domain": query_otx_domain,
        "url": query_urlhaus,
        "hash": query_otx_hash,
    }

    func = dispatch.get(ioc_type)
    if func:
        return func(ioc_value)

    # 尝试自动检测
    detected = _detect_ioc_type(ioc_value)
    if detected and detected in dispatch:
        logger.info("自动检测 IOC 类型: %s → %s", ioc_value, detected)
        return dispatch[detected](ioc_value)

    return {
        "status": "error",
        "ioc_type": ioc_type,
        "ioc_value": ioc_value,
        "malicious": None,
        "error": f"不支持的 IOC 类型: '{ioc_type}'，支持 ip/domain/url/hash",
    }
