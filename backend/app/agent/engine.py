"""
2.4 / 3.1 ReAct Agent 引擎 — AgentEngine

Thought → Action → Observe 循环实现。
支持任务类型自动识别、结果聚合、置信度计算。
"""
import os
import re
import time
import json
import logging
from typing import Optional, Callable

from .llm import LLMClient
from .schemas import tool_registry, ToolRegistry

logger = logging.getLogger(__name__)

# Prompts 目录
_PROMPTS_DIR = os.path.join(os.path.dirname(__file__), "prompts")

# 任务类型 → Prompt 文件映射
_PROMPT_FILES = {
    "vulnerability_detection": "code_audit.txt",
    "malware_analysis": "malware_analysis.txt",
}

# ------------------------------------------------------------------
# 3.1.1 任务类型自动识别 — 恶意代码检测模式
# ------------------------------------------------------------------
_MALWARE_CODE_PATTERNS = [
    # C2 通信 / 数据外传特征
    (r"(XMLHttpRequest|fetch)\s*\([^)]*\)", "HTTP 请求（数据外传/C2 通信）"),
    (r"new\s+WebSocket\s*\(", "WebSocket 连接（C2 实时通道）"),
    (r"document\.cookie", "Cookie 窃取"),
    (r"navigator\.userAgent", "浏览器指纹收集"),
    (r"window\.location", "页面 URL 收集"),
    # 键盘记录
    (r"(keydown|keyup|keypress|onkey)", "键盘事件监听（可能的键盘记录）"),
    (r"(GetAsyncKeyState|SetWindowsHookEx\s*\()", "Windows 键盘 Hook"),
    # 远程执行/下载
    (r"URLDownloadToFile", "Windows URL 下载 API"),
    (r"(Net\.WebClient|DownloadString|DownloadFile|WebClient)", ".NET Web 下载 API"),
    (r"ShellExecute\s*\(", "Shell 执行调用"),
    (r"CreateRemoteThread", "远程线程创建（代码注入）"),
    (r"VirtualAllocEx", "远程内存分配（代码注入）"),
    # 反弹 Shell / 远程控制
    (r"(cmd|powershell)\s*/c\s", "Windows 命令执行"),
    (r"IEX\s*\(.*DownloadString", "PowerShell 远程下载执行"),
    (r"(/bin/(ba)?sh|/bin/bash)\b", "Shell 调用"),
    (r"subprocess\.(call|Popen|run)\s*\(", "Python 子进程调用"),
    (r"os\.system\s*\(", "Python 系统命令调用"),
    (r"(wget|curl)\s+-", "文件下载命令"),
    (r"nc\s+-[nlvp].*\d{1,5}", "Netcat 反弹 Shell"),
    # 混淆/编码
    (r"base64.*decode.*eval", "Base64 解码后执行（混淆）"),
    (r"eval\s*\(\s*(atob|base64)", "解码后 eval 执行"),
    (r"exec\s*\(\s*.*base64", "Base64 解码后 exec"),
    # 持久化
    (r"(RegWrite|RegSetValue|registry|HKLM|HKCU)", "注册表操作（可能的持久化）"),
    (r"(schtasks|at\s+\d|cronexpression)", "计划任务（可能的持久化）"),
    # 进程注入/操纵
    (r"(OpenProcess|WriteProcessMemory|NtCreateThreadEx)", "进程操作 API"),
    # VBA 宏恶意特征
    (r"(AutoOpen|Auto_Open|Document_Open|Workbook_Open)", "Office 自动执行宏"),
    (r"WScript\.Shell", "VBA WScript Shell 调用"),
    # 信息窃取通用
    (r"(steal|窃取|盗取|collect.*password|harvest.*credential)", "信息窃取行为"),
]

# 恶意文件扩展名（文件路径检测用）
_MALWARE_FILE_EXTS = {".exe", ".dll", ".sys", ".bin", ".scr", ".pif",
                      ".docm", ".xlsm", ".pptm", ".xlam",
                      ".elf", ".so", ".dylib",
                      ".ps1", ".vbs", ".vba", ".bat", ".cmd", ".hta",
                      ".js", ".jar", ".wsf", ".ws"}

# 代码类文件扩展名（漏洞检测用）
_CODE_FILE_EXTS = {".py", ".java", ".js", ".ts", ".c", ".cpp", ".h", ".hpp",
                   ".go", ".rs", ".rb", ".php", ".swift", ".kt", ".cs",
                   ".sql", ".sh", ".yaml", ".yml", ".json", ".xml"}


class AgentEngine:
    """ReAct Agent 引擎。

    接收安全分析任务，加载 System Prompt，驱动 LLM 进行
    Thought → Action → Observe 循环推理。

    Parameters
    ----------
    llm : LLMClient | None
        复用外部 LLM 客户端；为 None 时自动创建默认实例。
    tool_reg : ToolRegistry | None
        工具注册器；为 None 时使用全局 tool_registry。
    max_steps : int
        最大 ReAct 步数（默认 10）。
    step_timeout : float
        单步操作超时（秒，默认 60）。
    """

    def __init__(
        self,
        llm: Optional[LLMClient] = None,
        tool_reg: Optional[ToolRegistry] = None,
        max_steps: int = 10,
        step_timeout: float = 60.0,
    ) -> None:
        self.llm = llm or LLMClient()
        self.tool_reg = tool_reg or tool_registry
        self.max_steps = max_steps
        self.step_timeout = step_timeout

        # 运行时状态
        self.task_type: str = ""
        self.messages: list[dict] = []
        self.steps: list[dict] = []
        self.step_count: int = 0
        self._start_time: float = 0.0

        # 工具执行器：{ tool_name: callable(**params) -> dict }
        self._tool_executors: dict[str, Callable] = {}

        # 自动注册已实现的工具（替换 _stub_executor 占位）
        self._auto_register_tools()

        # 循环控制状态
        self._recent_actions: list[str] = []          # 最近动作指纹，用于重复检测
        self._no_progress_count: int = 0               # 连续无进展步数
        self._fallback_count: int = 0                  # fallback 触发次数

        # 回调（WebSocket 推送）
        self._on_step: Optional[Callable[[dict], None]] = None

    # ------------------------------------------------------------------
    # 标准分析流程定义（供 fallback 使用）
    # ------------------------------------------------------------------
    _STANDARD_WORKFLOWS: dict[str, list[dict]] = {
        "vulnerability_detection": [
            {"step": 1, "action": "调用 scan_code 对代码进行静态安全扫描", "tool": "scan_code", "args_hint": "code和language参数"},
            {"step": 2, "action": "根据扫描结果，对发现的每个问题调用 query_cwe 获取弱点详情和修复建议", "tool": "query_cwe", "args_hint": "cwe_id参数"},
            {"step": 3, "action": "调用 query_cve 按关键字查找相关的历史 CVE 案例", "tool": "query_cve", "args_hint": "keyword参数"},
            {"step": 4, "action": "汇总所有工具结果，输出 JSON 格式的最终分析报告", "tool": None, "args_hint": None},
        ],
        "malware_analysis": [
            {"step": 1, "action": "调用 extract_file_features 提取文件基本信息、导入表和可疑字符串", "tool": "extract_file_features", "args_hint": "file_path参数"},
            {"step": 2, "action": "调用 extract_iocs 从文件字符串中提取 IP/域名/URL/Hash 等 IOC", "tool": "extract_iocs", "args_hint": "text参数"},
            {"step": 3, "action": "对提取到的每个 IOC 调用 query_threat_intel 查询威胁情报", "tool": "query_threat_intel", "args_hint": "ioc_type和ioc_value参数"},
            {"step": 4, "action": "调用 map_attack 将恶意行为映射到 ATT&CK 战术/技术", "tool": "map_attack", "args_hint": "behavior参数"},
            {"step": 5, "action": "调用 scan_yara 检测是否匹配已知恶意软件家族", "tool": "scan_yara", "args_hint": "file_path参数"},
            {"step": 6, "action": "汇总所有工具结果，输出 JSON 格式的最终分析报告", "tool": None, "args_hint": None},
        ],
    }

    # ------------------------------------------------------------------
    # 3.1.1 任务类型自动识别
    # ------------------------------------------------------------------
    @classmethod
    def _detect_task_type(cls, input_content: str) -> tuple[str, str]:
        """根据输入内容自动判断任务类型。

        检测策略（纯启发式，不调用 LLM）：
        1. 如果内容看起来像文件路径 → 根据扩展名判断
        2. 如果内容包含恶意行为特征 → malware_analysis
        3. 否则 → vulnerability_detection（默认）

        Returns
        -------
        tuple[str, str]
            (task_type, reason) — task_type 和判定原因
        """
        content = input_content.strip()

        # ---------- 策略 1：文件路径检测 ----------
        # 如果输入看起来像一个文件路径（无换行、无空格或少空格、带扩展名）
        if "\n" not in content and len(content) < 1024:
            ext = os.path.splitext(content)[1].lower()
            if ext in _MALWARE_FILE_EXTS:
                reason = f"文件路径指向可执行/恶意文件类型 ({ext})"
                logger.info("任务类型自动识别 → malware_analysis: %s", reason)
                return ("malware_analysis", reason)
            if ext in _CODE_FILE_EXTS:
                reason = f"文件路径指向源代码文件 ({ext})"
                logger.info("任务类型自动识别 → vulnerability_detection: %s", reason)
                return ("vulnerability_detection", reason)

        # ---------- 策略 2：恶意行为特征匹配 ----------
        matched_patterns: list[str] = []
        for pattern, description in _MALWARE_CODE_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                matched_patterns.append(description)

        # 至少匹配到 3 个恶意特征才判定为恶意分析（降低对含系统调用漏洞代码的误判）
        if len(matched_patterns) >= 3:
            reason = f"检测到恶意行为特征: {', '.join(matched_patterns[:5])}"
            logger.info("任务类型自动识别 → malware_analysis: %s", reason)
            return ("malware_analysis", reason)

        # ---------- 策略 3：默认代码漏洞检测 ----------
        if matched_patterns:
            reason = f"仅匹配 {len(matched_patterns)} 个恶意特征（需≥3），默认按代码漏洞检测"
        else:
            reason = "未检测到恶意特征，默认按代码漏洞检测"
        logger.info("任务类型自动识别 → vulnerability_detection: %s", reason)
        return ("vulnerability_detection", reason)

    # ------------------------------------------------------------------
    # 公开方法
    # ------------------------------------------------------------------
    def run(self, task_type: Optional[str] = None, input_content: str = "") -> dict:
        """执行安全分析任务并返回结构化结果。

        Parameters
        ----------
        task_type : str | None
            "vulnerability_detection" 或 "malware_analysis"。
            为 None 时自动识别任务类型。
        input_content : str
            源代码文本或文件内容（或文件路径）

        Returns
        -------
        dict
            包含 steps / result / usage / error 的完整结果
        """
        # --- 自动识别任务类型 ---
        if task_type is None:
            task_type, detect_reason = self._detect_task_type(input_content)
            logger.info("自动识别任务类型: %s → %s", detect_reason, task_type)
        else:
            detect_reason = f"由调用方指定: {task_type}"

        self.task_type = task_type
        self._start_time = time.time()

        # 初始化 prompt 和上下文
        system_prompt = self._load_prompt(task_type)
        tools = self.tool_reg.get_for_llm(task_type=task_type)

        self.messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": input_content},
        ]
        self.steps = []
        self.step_count = 0
        self._recent_actions = []
        self._no_progress_count = 0
        self._fallback_count = 0

        logger.info("Agent 启动 task_type=%s tools=%d", task_type, len(tools))

        # 主循环
        try:
            result = self._run_loop(tools)
        except Exception as e:
            logger.error("Agent 执行异常: %s", e)
            result = {"content": None, "error": str(e)}

        elapsed = round(time.time() - self._start_time, 1)

        # --- 分析结果聚合 ---
        aggregated = self._aggregate_results(task_type)

        # --- 置信度计算 ---
        confidence = self._calculate_confidence(
            task_type=task_type,
            aggregated=aggregated,
            final_result=result.get("content"),
        )

        # 推送完成/错误步骤
        if result.get("error"):
            self._push_step({
                "step_num": self.step_count,
                "type": "error",
                "data": {"message": result["error"], "elapsed_seconds": elapsed},
            })
        else:
            self._push_step({
                "step_num": self.step_count,
                "type": "done",
                "data": {
                    "message": "分析完成",
                    "elapsed_seconds": elapsed,
                    "total_steps": self.step_count,
                    "confidence": confidence["level"],
                    "confidence_score": confidence["score"],
                },
            })

        return {
            "task_type": task_type,
            "detect_reason": detect_reason,
            "steps": self.steps,
            "result": result.get("content"),
            "aggregated": aggregated,
            "confidence": confidence,
            "error": result.get("error"),
            "total_steps": self.step_count,
            "elapsed_seconds": elapsed,
            "usage": self.llm.total_usage,
        }

    def on_step(self, callback: Callable[[dict], None]) -> None:
        """注册步骤回调（供 WebSocket 实时推送）。"""
        self._on_step = callback

    def register_tool(self, name: str, executor: Callable[..., dict]) -> None:
        """注册一个工具的执行函数。

        工具链模块（module 4）完成后，通过此方法将真实工具注入 Agent。

        Parameters
        ----------
        name : str
            工具名称，必须与 Schema 中的名称一致。
        executor : callable
            工具执行函数，接收 ``**params`` 关键字参数，返回 dict 结果。
        """
        self._tool_executors[name] = executor
        logger.info("工具执行器已注册: %s", name)

    # ------------------------------------------------------------------
    # 3.1.2 分析结果聚合
    # ------------------------------------------------------------------
    def _aggregate_results(self, task_type: str) -> dict:
        """从多步工具调用结果中提取结构化关键发现。

        遍历 ReAct 循环中的 tool 消息，解析各工具的原始返回，
        按任务类型组织为结构化摘要。

        Returns
        -------
        dict
            包含 summary / findings / tool_call_stats 的结构化聚合结果
        """
        # 从 messages 中提取所有 tool 角色的结果
        tool_results: list[dict] = []
        for msg in self.messages:
            if msg.get("role") != "tool":
                continue
            try:
                parsed = json.loads(msg.get("content", "{}"))
            except (json.JSONDecodeError, TypeError):
                parsed = {"raw": str(msg.get("content", ""))[:500]}
            tool_results.append({
                "name": msg.get("name", "unknown"),
                "result": parsed,
            })

        # 统计工具调用
        tool_call_counts: dict[str, int] = {}
        for tr in tool_results:
            name = tr["name"]
            tool_call_counts[name] = tool_call_counts.get(name, 0) + 1

        # 按任务类型提取关键发现
        if task_type == "vulnerability_detection":
            key_findings = self._aggregate_vuln(tool_results)
            scan_only = [f for f in key_findings if f.get("source") == "scan_code"]
            summary = {
                "total_tool_calls": len(tool_results),
                "unique_tools_used": list(tool_call_counts.keys()),
                "tool_call_counts": tool_call_counts,
                "total_findings": len(key_findings),
                "scan_findings_count": len(scan_only),
                "high_risk_count": sum(1 for f in scan_only if f.get("severity") == "high"),
                "medium_risk_count": sum(1 for f in scan_only if f.get("severity") == "medium"),
                "low_risk_count": sum(1 for f in scan_only if f.get("severity") == "low"),
            }
        else:
            key_findings = self._aggregate_malware(tool_results)
            summary = {
                "total_tool_calls": len(tool_results),
                "unique_tools_used": list(tool_call_counts.keys()),
                "tool_call_counts": tool_call_counts,
                "extracted_features_count": len(key_findings.get("file_features", [])),
                "iocs_count": len(key_findings.get("iocs", [])),
                "threat_intel_count": len(key_findings.get("threat_intel_results", [])),
                "attack_techniques_count": len(key_findings.get("attack_techniques", [])),
                "yara_matches_count": len(key_findings.get("yara_matches", [])),
            }

        return {
            "summary": summary,
            "key_findings": key_findings,
            "tool_call_counts": tool_call_counts,
        }

    def _aggregate_vuln(self, tool_results: list[dict]) -> list[dict]:
        """聚合漏洞检测结果：提取 scan_code / query_cwe / query_cve 的关键数据。"""
        findings: list[dict] = []

        for tr in tool_results:
            name = tr["name"]
            result = tr.get("result", {})

            if name == "scan_code":
                raw_findings = result.get("findings", [])
                for f in raw_findings:
                    if not isinstance(f, dict):
                        continue
                    # 跳过无发现占位条目
                    if f.get("rule_id") == "none" or f.get("severity") == "info":
                        continue
                    findings.append({
                        "source": "scan_code",
                        "rule_id": f.get("rule_id", ""),
                        "severity": f.get("severity", "unknown"),
                        "message": f.get("message", ""),
                        "cwe": f.get("cwe", ""),
                    })

            elif name == "query_cwe":
                cwe_data = result
                if isinstance(cwe_data, dict) and cwe_data.get("id"):
                    findings.append({
                        "source": "query_cwe",
                        "cwe_id": cwe_data.get("id", ""),
                        "cwe_name": cwe_data.get("name", ""),
                        "severity": cwe_data.get("severity", "unknown"),
                        "mitigation": cwe_data.get("mitigation", ""),
                    })

            elif name == "query_cve":
                cve_results = result.get("results", [])
                for cve in cve_results:
                    if isinstance(cve, dict):
                        findings.append({
                            "source": "query_cve",
                            "cve_id": cve.get("cve_id", ""),
                            "name": cve.get("name", ""),
                            "cvss": cve.get("cvss", 0),
                            "description": cve.get("description", ""),
                        })

        # 按严重度/置信度智能排序（惰性导入避免循环依赖）
        from ..services.sorting import sort_findings as _sort
        return _sort(findings)

    def _aggregate_malware(self, tool_results: list[dict]) -> dict:
        """聚合恶意分析结果：提取文件特征、IOC、威胁情报、ATT&CK、YARA。"""
        aggregated: dict = {
            "file_features": [],
            "iocs": [],
            "threat_intel_results": [],
            "attack_techniques": [],
            "yara_matches": [],
        }

        for tr in tool_results:
            name = tr["name"]
            result = tr.get("result", {})

            if name == "extract_file_features":
                aggregated["file_features"].append({
                    "file_type": result.get("file_type", "unknown"),
                    "file_size": result.get("file_size", 0),
                    "md5": result.get("md5", ""),
                    "sha256": result.get("sha256", ""),
                    "imports": result.get("imports", [])[:20],
                    "strings_of_interest": result.get("strings_of_interest", [])[:20],
                })

            elif name == "extract_iocs":
                for ioc in result.get("iocs", []):
                    if isinstance(ioc, dict):
                        aggregated["iocs"].append({
                            "type": ioc.get("type", ""),
                            "value": ioc.get("value", ""),
                        })

            elif name == "query_threat_intel":
                aggregated["threat_intel_results"].append({
                    "ioc_type": result.get("ioc_type", ""),
                    "ioc_value": result.get("ioc_value", ""),
                    "malicious": result.get("malicious", False),
                    "sources": result.get("sources", []),
                    "pulse_count": result.get("pulse_count", 0),
                })

            elif name == "map_attack":
                if result.get("technique_id"):
                    aggregated["attack_techniques"].append({
                        "technique_id": result.get("technique_id", ""),
                        "technique_name": result.get("technique_name", ""),
                        "tactic": result.get("tactic", ""),
                    })

            elif name == "scan_yara":
                for match in result.get("matches", []):
                    if isinstance(match, dict):
                        aggregated["yara_matches"].append({
                            "rule_name": match.get("rule_name", ""),
                            "description": match.get("description", ""),
                        })

        return aggregated

    # ------------------------------------------------------------------
    # 3.1.3 置信度计算
    # ------------------------------------------------------------------
    def _calculate_confidence(
        self,
        task_type: str,
        aggregated: dict,
        final_result: Optional[str],
    ) -> dict:
        """综合多维度计算分析置信度。

        四个评分维度：
        1. 工具覆盖度 (0-30)：使用了多少种不同工具
        2. 证据充分度 (0-30)：工具返回的实质性发现数量
        3. 分析深度   (0-20)：ReAct 步数是否充分
        4. LLM 自评   (0-20)：解析 LLM 最终输出中的置信度表述

        Returns
        -------
        dict
            {"level": "high"|"medium"|"low", "score": int, "factors": [...]}
        """
        factors: list[dict] = []
        score = 0

        tool_counts: dict[str, int] = aggregated.get("tool_call_counts", {})
        unique_tools = list(tool_counts.keys())
        total_tool_calls = sum(tool_counts.values())

        # ---------- 维度 1：工具覆盖度 (0-30) ----------
        if task_type == "vulnerability_detection":
            # 3 种工具：scan_code, query_cwe, query_cve
            coverage_score = min(30, len(unique_tools) * 10)
        else:
            # 5 种工具：extract_file_features, extract_iocs, query_threat_intel,
            #           map_attack, scan_yara
            coverage_score = min(30, len(unique_tools) * 6)
        score += coverage_score
        factors.append({
            "dimension": "tool_coverage",
            "score": coverage_score,
            "max": 30,
            "detail": f"使用了 {len(unique_tools)} 种工具 ({', '.join(unique_tools)})，共调用 {total_tool_calls} 次",
        })

        # ---------- 维度 2：证据充分度 (0-30) ----------
        evidence_score = 0
        summary = aggregated.get("summary", {})

        if task_type == "vulnerability_detection":
            scan_count = summary.get("scan_findings_count", 0)
            cve_cwe_count = summary.get("total_findings", 0) - scan_count
            evidence_score = min(30, scan_count * 10 + cve_cwe_count * 5)
            detail = f"扫描发现 {scan_count} 条，CWE/CVE 关联 {cve_cwe_count} 条"
        else:
            iocs = summary.get("iocs_count", 0)
            ti = summary.get("threat_intel_count", 0)
            attack = summary.get("attack_techniques_count", 0)
            yara = summary.get("yara_matches_count", 0)
            evidence_score = min(30, iocs * 5 + ti * 10 + attack * 8 + yara * 7)
            detail = f"IOC {iocs} 个, 威胁情报 {ti} 条, ATT&CK {attack} 项, YARA {yara} 项"

        score += evidence_score
        factors.append({
            "dimension": "evidence_quality",
            "score": evidence_score,
            "max": 30,
            "detail": detail,
        })

        # ---------- 维度 3：分析深度 (0-20) ----------
        depth_score = min(20, self.step_count * 4)
        score += depth_score
        factors.append({
            "dimension": "analysis_depth",
            "score": depth_score,
            "max": 20,
            "detail": f"ReAct 共 {self.step_count} 步",
        })

        # ---------- 维度 4：LLM 自评 (0-20) ----------
        llm_self_score = self._parse_llm_confidence(final_result)
        score += llm_self_score
        factors.append({
            "dimension": "llm_self_assessment",
            "score": llm_self_score,
            "max": 20,
            "detail": f"从 LLM 输出解析置信度得分: {llm_self_score}/20",
        })

        # ---------- 综合评级 ----------
        if score >= 70:
            level = "high"
        elif score >= 40:
            level = "medium"
        else:
            level = "low"

        return {
            "level": level,
            "score": score,
            "max_score": 100,
            "factors": factors,
        }

    @staticmethod
    def _parse_llm_confidence(final_result: Optional[str]) -> int:
        """从 LLM 最终输出中解析置信度表述。

        扫描文本中的置信度关键词，返回 0-20 的评分。
        """
        if not final_result:
            return 5  # 无输出 → 极低

        text = final_result.lower()

        # 高置信度关键词
        high_patterns = [
            r'"confidence"\s*:\s*"high"',
            r"high confidence",
            r"置信度[：:]\s*(高|high)",
            r"confidence[：:]\s*(高|high)",
            r"确定(性|度)[：:]\s*(高|high)",
        ]
        for p in high_patterns:
            if re.search(p, text):
                return 20

        # 中置信度关键词
        medium_patterns = [
            r'"confidence"\s*:\s*"medium"',
            r"medium confidence",
            r"置信度[：:]\s*(中|medium)",
            r"confidence[：:]\s*(中|medium)",
        ]
        for p in medium_patterns:
            if re.search(p, text):
                return 12

        # 低置信度关键词
        low_patterns = [
            r'"confidence"\s*:\s*"low"',
            r"low confidence",
            r"置信度[：:]\s*(低|low)",
            r"confidence[：:]\s*(低|low)",
            r"不确定",
            r"需人工",
            r"uncertain",
            r"needs manual",
        ]
        for p in low_patterns:
            if re.search(p, text):
                return 5

        # 未明确标注 → 默认中等偏低
        return 10

    # ------------------------------------------------------------------
    # 内部方法
    # ------------------------------------------------------------------
    def _load_prompt(self, task_type: str) -> str:
        """加载对应任务类型的 System Prompt。"""
        filename = _PROMPT_FILES.get(task_type)
        if not filename:
            raise ValueError(f"未知任务类型: {task_type}，可选 {list(_PROMPT_FILES)}")

        path = os.path.join(_PROMPTS_DIR, filename)
        if not os.path.exists(path):
            raise FileNotFoundError(f"Prompt 文件不存在: {path}")

        with open(path, "r", encoding="utf-8") as f:
            return f.read()

    def _run_loop(self, tools: list[dict]) -> dict:
        """主 ReAct 循环：Thought → Action → Observe。

        循环控制：
        - 最多 self.max_steps 步
        - 总超时 self.step_timeout * self.max_steps 秒
        - 检测重复动作（相同工具+相同参数连续调用）
        - 连续 3 步无进展 → 注入引导消息
        """
        total_timeout = self.step_timeout * self.max_steps

        while self.step_count < self.max_steps:
            self.step_count += 1

            # --- 超时检查 ---
            elapsed_total = time.time() - self._start_time
            if elapsed_total > total_timeout:
                return {"content": None, "error": f"分析超时 ({round(elapsed_total)}s > {round(total_timeout)}s)"}

            # --- 兜底检查：连续 3 步无进展 ---
            if self._no_progress_count >= 3:
                self._apply_fallback()

            # ------ Thought 阶段 ------
            thought_result = self._do_thought(tools)
            if thought_result["error"]:
                return {"content": None, "error": thought_result["error"]}

            if thought_result["is_final"]:
                return {"content": thought_result["content"], "error": None}

            # ------ Action 阶段：执行工具 ------
            tool_calls = thought_result.get("tool_calls", [])
            if not tool_calls:
                self.messages.append({
                    "role": "user",
                    "content": "请继续分析。如果分析已完成，请输出最终报告。",
                })
                self._no_progress_count += 1
                continue

            # --- 重复动作检测 ---
            fingerprint = self._action_fingerprint(tool_calls)
            if self._is_duplicate_action(fingerprint):
                logger.warning("检测到重复动作: %s", fingerprint)
                self.messages.append({
                    "role": "user",
                    "content": "你刚才已经调用过相同的工具和参数。请换一个角度分析，或基于已有结果给出最终结论。",
                })
                self._no_progress_count += 1
                self._push_step({
                    "step_num": self.step_count,
                    "type": "thought",
                    "data": {"content": "[系统] 检测到重复动作，已提示 Agent 切换策略", "tool_calls_requested": []},
                })
                continue

            self._recent_actions.append(fingerprint)
            if len(self._recent_actions) > 5:
                self._recent_actions.pop(0)

            action_results = self._do_action(tool_calls)

            # --- 进展判断：工具是否返回了实质性结果 ---
            if self._is_progress(action_results):
                self._no_progress_count = 0
            else:
                self._no_progress_count += 1

            # ------ Observe 阶段：反馈结果 ------
            self._do_observe(tool_calls, action_results)

        return {"content": None, "error": f"达到最大步数限制 ({self.max_steps})，分析未完成"}

    # ------------------------------------------------------------------
    # 循环控制辅助方法
    # ------------------------------------------------------------------
    @staticmethod
    def _action_fingerprint(tool_calls: list[dict]) -> str:
        """生成工具调用的唯一指纹（用于重复检测）。"""
        parts = []
        for tc in tool_calls:
            args_str = json.dumps(tc.get("arguments", {}), sort_keys=True, ensure_ascii=False)
            parts.append(f"{tc['name']}:{args_str}")
        return "|".join(parts)

    def _is_duplicate_action(self, fingerprint: str) -> bool:
        """检查最近 3 个动作中是否已有相同指纹。"""
        recent = self._recent_actions[-3:]
        return fingerprint in recent

    @staticmethod
    def _is_progress(action_results: list[dict]) -> bool:
        """判断工具返回是否有实质进展。

        视为有进展：
        - 任一工具返回了非空 result 且不是 not_implemented
        - 任一工具返回了 error（失败也是信息）
        """
        for r in action_results:
            if r.get("error"):
                return True  # 错误也是信号
            result = r.get("result", {})
            if isinstance(result, dict):
                status = result.get("status", "")
                if status != "not_implemented":
                    return True
            elif result is not None:
                return True
        return False

    def _apply_fallback(self) -> None:
        """3.1.4 兜底策略：连续 3 步无进展 → 逐步切换到标准分析流程。

        策略分级：
        1. 第一次触发：引导 Agent 执行标准流程中尚未调用的下一步工具
        2. 第二次触发：跳过剩余工具，引导 Agent 直接基于已有结果输出报告
        3. 第三次触发（最终兜底）：强制要求 Agent 立即输出 JSON 报告
        """
        self._fallback_count += 1
        workflow = self._STANDARD_WORKFLOWS.get(self.task_type, [])
        called_tools = self._get_called_tools()

        logger.warning(
            "连续 %d 步无进展，fallback #%d 触发（已调用工具: %s）",
            self._no_progress_count, self._fallback_count, list(called_tools),
        )

        # ---------- 第 1 次 fallback：引导下一步标准工具 ----------
        if self._fallback_count == 1 and workflow:
            pending = [w for w in workflow if w["tool"] and w["tool"] not in called_tools]
            if pending:
                next_step = pending[0]
                hint = ""
                if next_step["args_hint"]:
                    hint = f" 请根据已有信息填入 {next_step['args_hint']}。"
                fallback_msg = (
                    f"你已连续多步未能取得实质进展。现在请按照标准分析流程操作：\n\n"
                    f"第 {next_step['step']} 步：{next_step['action']}。{hint}\n\n"
                    f"如果你不知道该传什么参数，可以从 messages 中已有的分析数据中提取。"
                )
            else:
                fallback_msg = (
                    "所有标准分析工具已调用完毕。请停止尝试调用工具，"
                    "直接基于你已有的知识和全部工具返回结果，"
                    "按照 System Prompt 中要求的 JSON 格式输出最终分析报告。"
                    "如果确实无法确定某些结论，请标注置信度为 'low' 并说明原因。"
                )

        # ---------- 第 2 次 fallback：跳过剩余工具，直接输出 ----------
        elif self._fallback_count == 2:
            incomplete = [w for w in workflow if w["tool"] and w["tool"] not in called_tools]
            if incomplete:
                skipped = ", ".join(f"{w['tool']}(第{w['step']}步)" for w in incomplete)
                fallback_msg = (
                    f"你已触发兜底策略第 2 次。请跳过以下未完成的工具调用：{skipped}。\n\n"
                    "不要再调用任何工具了！直接基于现有的工具返回结果和你的专业知识，"
                    "按照 System Prompt 要求的 JSON 格式输出最终分析报告。"
                    "对于缺少数据支撑的结论，请降低置信度并标注'需人工确认'。"
                )
            else:
                fallback_msg = (
                    "你已触发兜底策略第 2 次。请立即停止调用工具，"
                    "基于全部已有数据，按照 System Prompt 中要求的 JSON 格式"
                    "输出最终分析报告。不要再尝试任何新的工具调用。"
                )

        # ---------- 第 3+ 次 fallback：最终强制输出 ----------
        else:
            fallback_msg = (
                f"【系统指令 — 第 {self._fallback_count} 次提醒】\n\n"
                "请立即停止一切工具调用尝试。你必须在下一步回复中直接输出 JSON 格式的"
                "最终分析报告（用 ```json 代码块包裹）。\n\n"
                "如果你确实因为工具不可用或数据不足而无法完成完整分析，请在 report 中：\n"
                "1. 列出已发现的问题（基于现有证据）\n"
                "2. 标注哪些结论需要人工验证（needs_manual_review: true）\n"
                "3. 将整体置信度设为 'low'\n\n"
                "不得再请求调用任何工具。这是强制指令。"
            )

        self.messages.append({"role": "user", "content": fallback_msg})
        self._no_progress_count = 0
        self._push_step({
            "step_num": self.step_count,
            "type": "thought",
            "data": {
                "content": f"[系统] 兜底策略 #{self._fallback_count} 触发",
                "tool_calls_requested": [],
            },
        })

    def _get_called_tools(self) -> set[str]:
        """从 messages 中提取已成功调用的工具名称集合。"""
        called: set[str] = set()
        for msg in self.messages:
            if msg.get("role") != "tool":
                continue
            name = msg.get("name", "")
            if name:
                # 只统计非错误返回（content 不是 error JSON）
                content = msg.get("content", "")
                try:
                    parsed = json.loads(content) if isinstance(content, str) else content
                except (json.JSONDecodeError, TypeError):
                    parsed = {}
                if not isinstance(parsed, dict) or "error" not in parsed:
                    called.add(name)
        return called

    def _do_thought(self, tools: list[dict]) -> dict:
        """Thought 阶段：调用 LLM 进行推理。

        Returns
        -------
        dict
            {"content": str | None, "tool_calls": list, "is_final": bool, "error": str | None}
        """
        try:
            response = self.llm.chat(self.messages, tools=tools)
        except Exception as e:
            logger.error("Thought 阶段 LLM 调用异常: %s", e)
            return {"content": None, "tool_calls": [], "is_final": False, "error": str(e)}

        if response.get("error"):
            return {"content": None, "tool_calls": [], "is_final": False, "error": response["error"]}

        content = response.get("content") or ""
        tool_calls = response.get("tool_calls") or []
        finish_reason = response.get("finish_reason", "stop")

        # 记录 Thought 步骤
        self._push_step({
            "step_num": self.step_count,
            "type": "thought",
            "data": {
                "content": content[:500],  # 截断保存
                "tool_calls_requested": [tc["name"] for tc in tool_calls],
                "finish_reason": finish_reason,
            },
        })

        # 把 assistant 回复加入消息历史
        assistant_msg: dict = {"role": "assistant", "content": content}
        if tool_calls:
            assistant_msg["tool_calls"] = [
                {
                    "id": tc["id"],
                    "type": "function",
                    "function": {"name": tc["name"], "arguments": json.dumps(tc["arguments"], ensure_ascii=False)},
                }
                for tc in tool_calls
            ]

        self.messages.append(assistant_msg)

        # 判断是否结束：finish_reason=stop 且无 tool_calls → 最终回复
        is_final = (finish_reason == "stop" or finish_reason is None) and not tool_calls

        return {
            "content": content,
            "tool_calls": tool_calls,
            "is_final": is_final,
            "error": None,
        }

    def _do_action(self, tool_calls: list[dict]) -> list[dict]:
        """Action 阶段：解析 LLM 的 tool_calls，调度工具执行。

        Parameters
        ----------
        tool_calls : list[dict]
            LLM 返回的 tool_calls，每项 {"id": str, "name": str, "arguments": dict}

        Returns
        -------
        list[dict]
            每个 tool_call 的执行结果
        """
        results: list[dict] = []

        for tc in tool_calls:
            name = tc["name"]
            args = tc.get("arguments", {})
            call_id = tc.get("id", "")

            # 1. 校验工具是否存在
            schema = self.tool_reg.get(name)
            if not schema:
                error_msg = f"未知工具: {name}"
                logger.warning(error_msg)
                results.append({"tool_call_id": call_id, "name": name, "error": error_msg})
                continue

            # 2. 校验参数
            validation = self.tool_reg.validate_args(name, args)
            if not validation["valid"]:
                error_msg = f"参数校验失败: {validation['error']}"
                logger.warning("%s.%s: %s", name, args, error_msg)
                results.append({"tool_call_id": call_id, "name": name, "error": error_msg})
                continue

            # 3. 执行工具
            start = time.time()
            try:
                executor = self._tool_executors.get(name)
                if executor:
                    output = executor(**args)
                else:
                    output = self._stub_executor(name, args)

                elapsed = round(time.time() - start, 2)
                results.append({
                    "tool_call_id": call_id,
                    "name": name,
                    "arguments": args,
                    "result": output,
                    "elapsed_seconds": elapsed,
                    "error": None,
                })
                logger.info("工具 %s 执行成功 (%.2fs)", name, elapsed)

            except Exception as e:
                logger.error("工具 %s 执行异常: %s", name, e)
                results.append({
                    "tool_call_id": call_id,
                    "name": name,
                    "arguments": args,
                    "result": None,
                    "elapsed_seconds": round(time.time() - start, 2),
                    "error": str(e),
                })

        # 记录 Action 步骤（包含工具执行结果摘要）
        action_summary = []
        for r in results:
            # 对 args 中的长值进行截断，避免 code 等字段导致 JSON 过大
            raw_args = r.get("arguments", {})
            truncated_args = {
                k: (str(v)[:200] + "...(已截断)" if len(str(v)) > 200 else v)
                for k, v in raw_args.items()
            }
            entry: dict = {"name": r["name"], "ok": r["error"] is None, "args": truncated_args}
            # 包含工具执行结果摘要，让前端能看到关键信息
            if r["error"] is None and r.get("result"):
                result = r["result"]
                if isinstance(result, dict):
                    # 提取关键信息
                    if "findings" in result:
                        entry["findings_count"] = len(result["findings"])
                    if "iocs" in result:
                        entry["iocs_count"] = len(result["iocs"])
                    if "results" in result:
                        entry["results_count"] = len(result["results"])
                    if "status" in result:
                        entry["status"] = result["status"]
                    if "techniques" in result:
                        entry["techniques_count"] = len(result["techniques"])
                    if "matches" in result:
                        entry["matches_count"] = len(result["matches"])
                    if "message" in result:
                        entry["message"] = str(result["message"])[:200]
                    # 保留完整结果的 JSON 摘要（截断防止过长）
                    entry["result_preview"] = json.dumps(result, ensure_ascii=False)[:500]
                else:
                    entry["result_preview"] = str(result)[:200]
            elif r["error"]:
                entry["error"] = r["error"]
            action_summary.append(entry)
        self._push_step({
            "step_num": self.step_count,
            "type": "action",
            "data": {"results": action_summary},
        })

        return results

    def _auto_register_tools(self) -> None:
        """自动注册已实现的工具，替换占位 stub executor。

        逐个尝试导入工具模块，单个失败不影响其他工具注册。
        注册后 _do_action 将调用真实实现而非 _stub_executor。
        """
        tool_imports = [
            ("scan_code", "app.tools.scanner", "scan_code"),
            ("query_cve", "app.tools.cve_query", "query_cve"),
            ("query_cwe", "app.tools.cve_query", "query_cwe"),
            ("query_threat_intel", "app.tools.threat_intel", "query_threat_intel"),
            ("extract_iocs", "app.tools.ioc_extractor", "extract_iocs"),
            ("map_attack", "app.tools.attack_mapper", "map_attack"),
            ("scan_yara", "app.tools.yara_scanner", "scan_yara"),
            ("extract_file_features", "app.tools.file_analysis", "extract_file_features"),
        ]

        registered = 0
        import importlib
        for tool_name, module_path, func_name in tool_imports:
            try:
                mod = importlib.import_module(module_path)
                func = getattr(mod, func_name)
                self._tool_executors[tool_name] = func
                registered += 1
            except Exception as e:
                logger.warning("工具 '%s' 自动注册失败: %s", tool_name, e)

        if registered > 0:
            logger.info("自动注册 %d/%d 个工具执行器", registered, len(tool_imports))

    def _stub_executor(self, name: str, args: dict) -> dict:
        """占位执行器：当工具尚未实现时返回提示信息。

        模块 4 完成后，用 register_tool() 注入真实实现即可替换。
        """
        schema = self.tool_reg.get(name)
        description = schema["function"]["description"] if schema else ""
        return {
            "status": "not_implemented",
            "message": f"工具 '{name}' 尚未实现。{description}",
            "called_with": args,
        }

    def _do_observe(self, tool_calls: list[dict], action_results: list[dict]) -> None:
        """Observe 阶段：将工具返回结果格式化后反馈给 LLM。

        将每个 tool_call 的结果作为 role=tool 的消息追加到 messages 中，
        LLM 在下一步 Thought 中可以看到这些观察结果。
        """
        for tc, result in zip(tool_calls, action_results):
            call_id = tc.get("id", "")
            name = tc.get("name", "unknown")

            if result["error"]:
                observation = json.dumps({"error": result["error"]}, ensure_ascii=False)
            else:
                observation = json.dumps(result.get("result", {}), ensure_ascii=False)

            self.messages.append({
                "role": "tool",
                "tool_call_id": call_id,
                "name": name,
                "content": observation,
            })

        # 记录 Observe 步骤（包含完整工具结果，不只是 preview）
        observe_summary = []
        for r in action_results:
            result_data = r.get("result", {})
            error = r.get("error")
            entry = {
                "tool": r["name"],
                "result_preview": (
                    json.dumps(result_data, ensure_ascii=False)[:200]
                    if error is None else f"ERROR: {error}"
                ),
            }
            # 包含完整结果（截断到合理长度）
            if error is None and result_data:
                full_result = json.dumps(result_data, ensure_ascii=False)
                entry["result_full"] = full_result[:2000]  # 完整结果，最多2000字符
                # 提取关键摘要信息
                if isinstance(result_data, dict):
                    if "findings" in result_data:
                        entry["findings_count"] = len(result_data["findings"])
                    if "iocs" in result_data:
                        entry["iocs_count"] = len(result_data["iocs"])
                    if "results" in result_data:
                        entry["results_count"] = len(result_data["results"])
                    if "techniques" in result_data:
                        entry["techniques_count"] = len(result_data["techniques"])
                    if "matches" in result_data:
                        entry["matches_count"] = len(result_data["matches"])
            observe_summary.append(entry)
        self._push_step({
            "step_num": self.step_count,
            "type": "observation",
            "data": {"observations": observe_summary},
        })

    def _push_step(self, step: dict) -> None:
        """推送步骤到存储和回调。"""
        self.steps.append(step)
        if self._on_step:
            try:
                self._on_step(step)
            except Exception as e:
                logger.warning("步骤回调异常: %s", e)
