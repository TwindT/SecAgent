"""
任务执行器 — 桥接 Agent 引擎与 WebSocket 推送。

将引擎的 on_step 回调连接到 WebSocket ConnectionManager，
实现分析过程的实时推送。

WebSocket 推送消息格式（符合 2.5 约定）：
    {
        "type": "thought" | "action" | "observation" | "done" | "error",
        "data": {
            "step_num": int,
            "timestamp": "ISO8601",
            ...   // 各类型特有字段
        }
    }
"""

import logging
from datetime import datetime, timezone
from typing import Callable, Optional

from ..agent.engine import AgentEngine
from ..agent.llm import LLMClient
from ..websocket import manager

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------
# 工具注册（将已实现的工具注入 Agent 引擎）
# ------------------------------------------------------------------

def _register_tools(engine: AgentEngine) -> None:
    """将已实现的工具注册到引擎，替换占位 stub executor。"""
    try:
        from ..tools import scan_code, query_cve, query_cwe, query_threat_intel, extract_iocs, map_attack, scan_yara
        engine.register_tool("scan_code", scan_code)
        engine.register_tool("query_cve", query_cve)
        engine.register_tool("query_cwe", query_cwe)
        engine.register_tool("query_threat_intel", query_threat_intel)
        engine.register_tool("extract_iocs", extract_iocs)
        engine.register_tool("map_attack", map_attack)
        engine.register_tool("scan_yara", scan_yara)
        logger.info("已注册 %d 个工具执行器", 7)
    except Exception as e:
        logger.warning("工具注册失败，将使用 stub executor: %s", e)


def _make_ws_callback(task_id: str):
    """创建 WebSocket 推送回调闭包。

    返回一个 callable，接收引擎的 step dict，
    按照约定格式标准化后转发到 WebSocket 管理器广播给订阅该任务的客户端。

    推送数据结构（2.5 规范）：
        type: "thought" | "action" | "observation" | "done" | "error"
        data:
            - step_num    : 步骤序号
            - timestamp   : ISO 8601 时间戳
            - thought     : { content, tool_calls_requested, finish_reason }
            - action      : { results: [{name, ok, args}] }
            - observation : { observations: [{tool, result_preview}] }
            - done        : { message, elapsed_seconds, total_steps }
            - error       : { message, elapsed_seconds }
    """

    async def _push(step: dict) -> None:
        """异步推送单个分析步骤到 WebSocket。"""
        # 将 step_num 合并到 data 中，顶层只保留 type + data
        payload_data: dict = {
            "step_num": step.get("step_num", 0),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        payload_data.update(step.get("data", {}))

        msg = {
            "type": step["type"],
            "data": payload_data,
        }
        await manager.send_message(task_id, msg)

    def on_step(step: dict) -> None:
        """同步回调入口（由引擎在同步上下文中调用）。"""
        import asyncio

        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.create_task(_push(step))
            else:
                asyncio.run(_push(step))
        except RuntimeError:
            # 无事件循环时创建新的
            asyncio.run(_push(step))
        except Exception as e:
            logger.warning("WebSocket 推送失败: %s", e)

    return on_step


def run_task_sync(
    task_id: str,
    task_type: str,
    input_content: str,
    llm: Optional[LLMClient] = None,
    max_steps: int = 10,
    on_step_callback: Optional[Callable[[dict], None]] = None,
) -> dict:
    """同步执行分析任务并实时推送过程到 WebSocket。

    Parameters
    ----------
    task_id : str
        任务唯一标识，对应 WebSocket 订阅路径。
    task_type : str
        "vulnerability_detection" 或 "malware_analysis"
    input_content : str
        待分析的源代码或文件内容。
    llm : LLMClient | None
        复用 LLM 客户端，为 None 时自动创建。
    max_steps : int
        最大 ReAct 步数。
    on_step_callback : Callable | None
        额外的步骤回调（如 DB 存储），与 WebSocket 推送并行调用。

    Returns
    -------
    dict
        引擎完整分析结果。
    """
    engine = AgentEngine(llm=llm, max_steps=max_steps)

    # 注册已实现的工具
    _register_tools(engine)

    # 注入 WebSocket 回调
    ws_cb = _make_ws_callback(task_id)

    def combined_callback(step: dict) -> None:
        """同时触发 WebSocket 推送和额外的步骤回调。"""
        ws_cb(step)
        if on_step_callback:
            try:
                on_step_callback(step)
            except Exception as e:
                logger.warning("额外步骤回调异常: %s", e)

    engine.on_step(combined_callback)

    logger.info("开始执行任务: task_id=%s type=%s", task_id, task_type)

    result = engine.run(task_type=task_type, input_content=input_content)

    logger.info(
        "任务执行完成: task_id=%s steps=%d elapsed=%ss",
        task_id, result["total_steps"], result["elapsed_seconds"],
    )

    return result
