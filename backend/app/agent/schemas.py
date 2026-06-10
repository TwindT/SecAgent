"""
2.3 Function Calling Schema 定义 + 工具注册器 (ToolRegistry)

为 6 个安全分析工具定义标准的 OpenAI/DashScope Function Calling Schema，
并提供统一的注册、查询和参数校验机制。
"""

from typing import Any, Optional
import json
import logging

logger = logging.getLogger(__name__)

# ==============================================================================
# 工具 Schema 定义（OpenAI Function Calling 格式）
# ==============================================================================

SCAN_CODE_SCHEMA = {
    "type": "function",
    "function": {
        "name": "scan_code",
        "description": "对源代码进行静态安全扫描（调用 semgrep/bandit）。检测 SQL 注入、XSS、命令注入、路径遍历、硬编码密钥等常见安全漏洞。",
        "parameters": {
            "type": "object",
            "properties": {
                "code": {
                    "type": "string",
                    "description": "待扫描的源代码文本",
                },
                "language": {
                    "type": "string",
                    "enum": ["python", "java", "javascript", "c", "auto"],
                    "description": "编程语言，'auto' 表示自动识别",
                },
            },
            "required": ["code", "language"],
        },
    },
}

QUERY_CVE_SCHEMA = {
    "type": "function",
    "function": {
        "name": "query_cve",
        "description": "查询 NVD CVE 漏洞数据库，获取漏洞详情、CVSS 评分、影响范围和修复信息。",
        "parameters": {
            "type": "object",
            "properties": {
                "cve_id": {
                    "type": "string",
                    "description": "CVE 编号，如 'CVE-2021-44228'。与 keyword 二选一。",
                },
                "keyword": {
                    "type": "string",
                    "description": "按关键字搜索 CVE，如 'SQL injection flask'。与 cve_id 二选一。",
                },
            },
        },
    },
}

QUERY_CWE_SCHEMA = {
    "type": "function",
    "function": {
        "name": "query_cwe",
        "description": "查询 MITRE CWE 弱点分类库，获取弱点详细描述、常见后果、缓解措施和代码示例。",
        "parameters": {
            "type": "object",
            "properties": {
                "cwe_id": {
                    "type": "string",
                    "description": "CWE 编号，如 'CWE-89'（SQL 注入）。支持常见安全弱点的快速查询。",
                },
            },
            "required": ["cwe_id"],
        },
    },
}

EXTRACT_FILE_FEATURES_SCHEMA = {
    "type": "function",
    "function": {
        "name": "extract_file_features",
        "description": "提取文件的静态特征信息。包括：文件类型识别（magic bytes）、PE/ELF 导入表与节区、可打印字符串、Office 宏代码、编译时间戳等。这是恶意代码分析的第一步。",
        "parameters": {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "待分析文件的本地路径",
                },
            },
            "required": ["file_path"],
        },
    },
}

EXTRACT_IOCS_SCHEMA = {
    "type": "function",
    "function": {
        "name": "extract_iocs",
        "description": "从文本中提取失陷指标（IOC），包括：IPv4 地址、域名（FQDN）、完整 URL、MD5/SHA1/SHA256 文件哈希。自动分类并去重后返回。",
        "parameters": {
            "type": "object",
            "properties": {
                "text": {
                    "type": "string",
                    "description": "待提取 IOC 的文本内容（如文件中的可打印字符串、代码注释等）",
                },
            },
            "required": ["text"],
        },
    },
}

QUERY_THREAT_INTEL_SCHEMA = {
    "type": "function",
    "function": {
        "name": "query_threat_intel",
        "description": "查询威胁情报平台（AlienVault OTX / URLhaus），检查 IP、域名、URL 或文件 Hash 是否已知恶意，返回信誉判定和关联的恶意活动信息。",
        "parameters": {
            "type": "object",
            "properties": {
                "ioc_type": {
                    "type": "string",
                    "enum": ["ip", "domain", "url", "hash"],
                    "description": "IOC 类型",
                },
                "ioc_value": {
                    "type": "string",
                    "description": "IOC 的具体值，如 '192.168.1.1'、'evil.example.com'、'https://malware.site/payload' 或文件哈希",
                },
            },
            "required": ["ioc_type", "ioc_value"],
        },
    },
}

MAP_ATTACK_SCHEMA = {
    "type": "function",
    "function": {
        "name": "map_attack",
        "description": "将恶意行为描述映射到 MITRE ATT&CK Enterprise 框架的战术（Tactic）和技术（Technique），返回技术 ID、名称和所属战术阶段。",
        "parameters": {
            "type": "object",
            "properties": {
                "behavior": {
                    "type": "string",
                    "description": "恶意行为描述，如 'credential dumping'、'remote file download via URLDownloadToFile'、'registry run key persistence'",
                },
            },
            "required": ["behavior"],
        },
    },
}

SCAN_YARA_SCHEMA = {
    "type": "function",
    "function": {
        "name": "scan_yara",
        "description": "使用 YARA 规则扫描文件，检测是否匹配已知恶意软件家族特征。规则库覆盖常见远控木马、下载器、信息窃取器等恶意软件类别。",
        "parameters": {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "待扫描的文件本地路径",
                },
            },
            "required": ["file_path"],
        },
    },
}

# ==============================================================================
# 工具分组（用于不同任务类型分发）
# ==============================================================================

CODE_AUDIT_TOOLS = ["scan_code", "query_cve", "query_cwe"]
MALWARE_ANALYSIS_TOOLS = [
    "extract_file_features",
    "extract_iocs",
    "query_threat_intel",
    "map_attack",
    "scan_yara",
]

# ==============================================================================
# 全部 Schema 注册表
# ==============================================================================

ALL_SCHEMAS = [
    SCAN_CODE_SCHEMA,
    QUERY_CVE_SCHEMA,
    QUERY_CWE_SCHEMA,
    EXTRACT_FILE_FEATURES_SCHEMA,
    EXTRACT_IOCS_SCHEMA,
    QUERY_THREAT_INTEL_SCHEMA,
    MAP_ATTACK_SCHEMA,
    SCAN_YARA_SCHEMA,
]

_SCHEMA_BY_NAME: dict[str, dict] = {}


def _build_index() -> None:
    """构建 Schema 名称索引（首次访问时自动调用）。"""
    global _SCHEMA_BY_NAME
    if _SCHEMA_BY_NAME:
        return
    for s in ALL_SCHEMAS:
        name = s["function"]["name"]
        _SCHEMA_BY_NAME[name] = s


def get_schema(name: str) -> Optional[dict]:
    """按名称查询单个工具 Schema。"""
    _build_index()
    return _SCHEMA_BY_NAME.get(name)


def get_all_schemas() -> list[dict]:
    """获取全部工具 Schema 列表。"""
    return list(ALL_SCHEMAS)


def get_schemas_for_task(task_type: str) -> list[dict]:
    """根据任务类型获取对应的工具 Schema 子集。

    task_type:
        "vulnerability_detection" → scan_code, query_cve, query_cwe
        "malware_analysis"         → extract_file_features, extract_iocs,
                                     query_threat_intel, map_attack, scan_yara
    """
    _build_index()
    if task_type == "vulnerability_detection":
        return [_SCHEMA_BY_NAME[n] for n in CODE_AUDIT_TOOLS if n in _SCHEMA_BY_NAME]
    if task_type == "malware_analysis":
        return [_SCHEMA_BY_NAME[n] for n in MALWARE_ANALYSIS_TOOLS if n in _SCHEMA_BY_NAME]
    return list(ALL_SCHEMAS)


# ==============================================================================
# ToolRegistry — 工具注册与校验
# ==============================================================================

class ToolRegistry:
    """工具注册器，管理 Schema 注册、查找与参数校验。"""

    def __init__(self) -> None:
        _build_index()
        self._schemas: dict[str, dict] = dict(_SCHEMA_BY_NAME)

    # ------------------------------------------------------------------
    # 注册
    # ------------------------------------------------------------------
    def register(self, schema: dict) -> None:
        """注册一个工具 Schema（覆盖同名已有 Schema）。"""
        name = schema["function"]["name"]
        self._schemas[name] = schema
        _SCHEMA_BY_NAME[name] = schema
        logger.info("工具已注册: %s", name)

    def unregister(self, name: str) -> bool:
        """注销一个工具，返回是否成功。"""
        removed = self._schemas.pop(name, None) is not None
        if removed:
            _SCHEMA_BY_NAME.pop(name, None)
            logger.info("工具已注销: %s", name)
        return removed

    # ------------------------------------------------------------------
    # 查询
    # ------------------------------------------------------------------
    def get(self, name: str) -> Optional[dict]:
        """按名称获取工具 Schema。"""
        return self._schemas.get(name)

    def list_tools(self) -> list[str]:
        """列出所有已注册工具的名称。"""
        return list(self._schemas.keys())

    def get_for_llm(
        self,
        task_type: Optional[str] = None,
        tool_names: Optional[list[str]] = None,
    ) -> list[dict]:
        """获取供 LLM 使用的工具 Schema 列表。

        task_type: 任务类型，自动筛选对应的工具子集，为 None 时返回全部
        tool_names: 指定工具名称列表，为 None 时不过滤
        """
        if tool_names:
            schemas = [self._schemas[n] for n in tool_names if n in self._schemas]
        elif task_type:
            schemas = get_schemas_for_task(task_type)
        else:
            schemas = list(self._schemas.values())
        return schemas

    # ------------------------------------------------------------------
    # 参数校验
    # ------------------------------------------------------------------
    def validate_args(self, name: str, arguments: dict) -> dict:
        """校验工具调用参数，返回 {"valid": bool, "error": str | None}。

        校验逻辑：
        1. 检查工具是否存在
        2. 检查 required 参数是否齐全
        3. 检查参数类型是否匹配（基本类型检查）
        """
        schema = self._schemas.get(name)
        if not schema:
            return {"valid": False, "error": f"未知工具: {name}"}

        props = schema["function"]["parameters"].get("properties", {})
        required = schema["function"]["parameters"].get("required", [])

        # 检查必填参数
        for param in required:
            if param not in arguments or arguments[param] is None:
                return {"valid": False, "error": f"缺少必填参数: {param}"}

        # 基本类型检查
        for key, value in arguments.items():
            if key not in props:
                continue
            param_def = props[key]

            # string 类型校验
            if param_def.get("type") == "string" and not isinstance(value, str):
                return {"valid": False, "error": f"参数 {key} 应为字符串类型"}

            # enum 校验
            if "enum" in param_def:
                allowed = param_def["enum"]
                if value not in allowed:
                    return {"valid": False, "error": f"参数 {key} 值 '{value}' 不在允许范围 {allowed}"}

        return {"valid": True, "error": None}

    # ------------------------------------------------------------------
    # 序列化
    # ------------------------------------------------------------------
    def to_json(self) -> str:
        """将所有 Schema 序列化为 JSON 字符串（调试用）。"""
        return json.dumps(list(self._schemas.values()), indent=2, ensure_ascii=False)

    def __len__(self) -> int:
        return len(self._schemas)

    def __contains__(self, name: str) -> bool:
        return name in self._schemas


# ==============================================================================
# 全局默认注册器实例
# ==============================================================================

tool_registry = ToolRegistry()
