"""
3.4 IOC 提取工具 — 从文本中提取失陷指标（IOC）。

支持 IPv4、域名、URL、MD5/SHA1/SHA256 Hash 的自动识别、提取、去重和分类。
提供 extract_iocs 工具入口函数，统一由 AgentEngine 通过 register_tool() 调用。
"""

import re
import logging

logger = logging.getLogger(__name__)

# ======================================================================
# 正则模式（按 IOC 类型分组）
# ======================================================================

# IPv4：1.0.0.0 ~ 255.255.255.255
_IPV4_RE = re.compile(
    r"\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
    r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
    r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
    r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)

# 域名（FQDN）：含至少一个点，不含空格和 @
_DOMAIN_RE = re.compile(
    r"\b(?!https?://)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}\b"
)

# URL：http/https + 可选的完整路径
_URL_RE = re.compile(
    r"https?://(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}(?:/[^\s\]\)\"'<>]*)?"
)

# MD5 Hash：32 位十六进制
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")

# SHA1 Hash：40 位十六进制
_SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")

# SHA256 Hash：64 位十六进制
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")


def _extract_ipv4(text: str) -> list[str]:
    """提取所有 IPv4 地址，排除 0.0.0.0 和 255.255.255.255 等无效地址。"""
    matches = _IPV4_RE.findall(text)
    ips = {".".join(m) for m in matches}
    # 过滤掉特征不明显的保留地址
    excluded = {"0.0.0.0", "255.255.255.255", "127.0.0.1"}
    ips -= excluded
    # 过滤掉以 0 开头的段（非标准表示，通常是版本号或数学表达式）
    valid = []
    for ip in sorted(ips):
        parts = ip.split(".")
        if all(not p.startswith("0") or p == "0" for p in parts):
            valid.append(ip)
    return valid


def _extract_domains(text: str, urls: set[str]) -> list[str]:
    """提取所有域名，排除已出现在 URL 中的域名。"""
    matches = _DOMAIN_RE.findall(text)
    domains = set()
    for m in matches:
        m_lower = m.lower().rstrip(".")
        # 排除 TLD 太短的匹配（可能是文件扩展名误报）
        tld = m_lower.split(".")[-1]
        if len(tld) < 2:
            continue
        # 排除常见误报：文件扩展名、编程关键字
        common_false = {
            "example.com", "test.com", "localhost.localdomain",
        }
        if m_lower in common_false:
            continue
        # 排除已经是 URL 一部分的域名
        is_part_of_url = any(m_lower in u for u in urls)
        if not is_part_of_url:
            domains.add(m_lower)
    return sorted(domains)


def _extract_urls(text: str) -> list[str]:
    """提取所有 HTTP/HTTPS URL。"""
    return sorted(set(_URL_RE.findall(text)))


def _extract_hashes(text: str) -> dict[str, list[str]]:
    """提取 MD5、SHA1、SHA256 哈希值并分类。

    注意：较长的匹配优先，避免 SHA256 被同时匹配为 SHA1 和 MD5。
    """
    sha256_matches = set(_SHA256_RE.findall(text))

    # 从文本中移除已匹配的 SHA256 区域后再匹配 SHA1
    temp_text = text
    for h in sha256_matches:
        temp_text = temp_text.replace(h, "")
    sha1_matches = set(_SHA1_RE.findall(temp_text))

    # 再移除 SHA1 后匹配 MD5
    for h in sha1_matches:
        temp_text = temp_text.replace(h, "")
    md5_matches = set(_MD5_RE.findall(temp_text))

    return {
        "md5": sorted(md5_matches),
        "sha1": sorted(sha1_matches),
        "sha256": sorted(sha256_matches),
    }


# ======================================================================
# extract_iocs — 统一入口（供 Agent Function Calling 调用）
# ======================================================================

def extract_iocs(text: str) -> dict:
    """从文本中提取失陷指标（IOC）。

    这是 Agent extract_iocs 工具的入口函数，
    签名与 EXTRACT_IOCS_SCHEMA 一致。

    自动识别并分类提取：
    - ipv4    : IPv4 地址
    - domains : 域名（FQDN）
    - urls    : 完整 URL
    - hashes  : MD5 / SHA1 / SHA256 文件哈希

    Parameters
    ----------
    text : str
        待提取 IOC 的文本内容。

    Returns
    -------
    dict
        {"status": "ok", "iocs": {...}, "total": int, "error": None}
        {"status": "error", "iocs": {}, "total": 0, "error": "reason"}
    """
    if not text or not isinstance(text, str):
        return {
            "status": "error",
            "iocs": {},
            "total": 0,
            "error": "输入文本为空或格式不正确",
        }

    try:
        urls = _extract_urls(text)
        ips = _extract_ipv4(text)
        domains = _extract_domains(text, set(urls))
        hashes = _extract_hashes(text)

        iocs = {
            "ipv4": ips,
            "domains": domains,
            "urls": urls,
            "hashes": hashes,
        }

        total = len(ips) + len(domains) + len(urls) + sum(len(v) for v in hashes.values())

        return {
            "status": "ok",
            "iocs": iocs,
            "total": total,
            "error": None,
        }

    except Exception as e:
        logger.exception("extract_iocs 执行异常")
        return {
            "status": "error",
            "iocs": {},
            "total": 0,
            "error": f"IOC 提取失败: {str(e)}",
        }
