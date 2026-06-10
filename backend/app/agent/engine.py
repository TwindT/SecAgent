"""
2.4 ReAct Agent 引擎 — AgentEngine

Thought → Action → Observe 循环实现。
"""
import os
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

        # 循环控制状态
        self._recent_actions: list[str] = []          # 最近动作指纹，用于重复检测
        self._no_progress_count: int = 0               # 连续无进展步数

        # 回调（WebSocket 推送）
        self._on_step: Optional[Callable[[dict], None]] = None

    # ------------------------------------------------------------------
    # 公开方法
    # ------------------------------------------------------------------
    def run(self, task_type: str, input_content: str) -> dict:
        """执行安全分析任务并返回结构化结果。

        Parameters
        ----------
        task_type : str
            "vulnerability_detection" 或 "malware_analysis"
        input_content : str
            源代码文本或文件内容

        Returns
        -------
        dict
            包含 steps / result / usage / error 的完整结果
        """
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

        logger.info("Agent 启动 task_type=%s tools=%d", task_type, len(tools))

        # 主循环
        try:
            result = self._run_loop(tools)
        except Exception as e:
            logger.error("Agent 执行异常: %s", e)
            result = {"content": None, "error": str(e)}

        return {
            "task_type": task_type,
            "steps": self.steps,
            "result": result.get("content"),
            "error": result.get("error"),
            "total_steps": self.step_count,
            "elapsed_seconds": round(time.time() - self._start_time, 1),
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
        """兜底策略：连续 3 步无进展 → 注入标准分析流程提示。"""
        logger.warning("连续 %d 步无进展，切换为标准分析流程", self._no_progress_count)
        fallback_msg = (
            "你已连续多步未能取得实质进展。请停止尝试调用工具，"
            "直接基于你已有的知识和分析结果，按照 System Prompt 中要求的 JSON 格式"
            "输出最终分析报告。如果确实无法确定某些结论，请标注置信度为 'low' 并说明原因。"
        )
        self.messages.append({"role": "user", "content": fallback_msg})
        self._no_progress_count = 0
        self._push_step({
            "step_num": self.step_count,
            "type": "thought",
            "data": {
                "content": f"[系统] 兜底策略触发：已注入标准分析流程提示",
                "tool_calls_requested": [],
            },
        })

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

        # 记录 Action 步骤
        action_summary = [
            {"name": r["name"], "ok": r["error"] is None, "args": r.get("arguments", {})}
            for r in results
        ]
        self._push_step({
            "step_num": self.step_count,
            "type": "action",
            "data": {"results": action_summary},
        })

        return results

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

        # 记录 Observe 步骤
        observe_summary = [
            {
                "tool": r["name"],
                "result_preview": (
                    json.dumps(r.get("result", {}), ensure_ascii=False)[:200]
                    if r["error"] is None else f"ERROR: {r['error']}"
                ),
            }
            for r in action_results
        ]
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
