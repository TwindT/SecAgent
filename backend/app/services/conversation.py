"""
对话管理模块 — 存储/加载对话历史、上下文窗口管理。

提供:
- ConversationManager: 对话 CRUD + Token 感知的上下文窗口截断
- 支持按 task_id 隔离对话，自动管理上下文长度
"""

import logging

from ..agent.llm import LLMClient
from ..models.database import Conversation, ConversationRole, SessionLocal

logger = logging.getLogger(__name__)

# 上下文窗口配置
DEFAULT_MAX_CONTEXT_TOKENS = 4000   # 对话历史最大 Token 数（不含 system prompt）
DEFAULT_RESERVED_TOKENS = 800       # 预留给回复的 Token
MAX_MESSAGE_LENGTH = 5000           # 单条消息最长字符数


class ConversationManager:
    """对话管理器 — 封装对话历史的存储、加载与上下文窗口管理。"""

    def __init__(
        self,
        max_context_tokens: int = DEFAULT_MAX_CONTEXT_TOKENS,
        reserved_tokens: int = DEFAULT_RESERVED_TOKENS,
    ):
        self.max_context_tokens = max_context_tokens
        self.reserved_tokens = reserved_tokens

    # ------------------------------------------------------------------
    # 存储
    # ------------------------------------------------------------------
    @staticmethod
    def add_message(
        task_id: int,
        role: str,
        content: str,
    ) -> Conversation:
        """存储一条对话消息到数据库，返回 ORM 对象。"""
        if len(content) > MAX_MESSAGE_LENGTH:
            content = content[:MAX_MESSAGE_LENGTH]

        db = SessionLocal()
        try:
            conv_role = ConversationRole.USER if role == "user" else ConversationRole.ASSISTANT
            msg = Conversation(task_id=task_id, role=conv_role, content=content)
            db.add(msg)
            db.commit()
            db.refresh(msg)
            return msg
        finally:
            db.close()

    # ------------------------------------------------------------------
    # 加载
    # ------------------------------------------------------------------
    @staticmethod
    def load_history(
        task_id: int,
        limit: int = 50,
    ) -> list[Conversation]:
        """加载指定任务的对话历史，按时间正序排列。"""
        db = SessionLocal()
        try:
            return (
                db.query(Conversation)
                .filter(Conversation.task_id == task_id)
                .order_by(Conversation.created_at.asc())
                .limit(limit)
                .all()
            )
        finally:
            db.close()

    @staticmethod
    def load_history_as_messages(
        task_id: int,
        limit: int = 50,
    ) -> list[dict]:
        """加载对话历史并转换为 LLM 可用的 messages 格式。"""
        history = ConversationManager.load_history(task_id, limit)
        messages: list[dict] = []
        for msg in history:
            role = "user" if msg.role == ConversationRole.USER else "assistant"
            messages.append({"role": role, "content": msg.content})
        return messages

    # ------------------------------------------------------------------
    # 上下文窗口管理
    # ------------------------------------------------------------------
    def build_context_messages(
        self,
        system_prompts: list[str],
        history: list[dict],
    ) -> list[dict]:
        """构建适合发送给 LLM 的完整消息列表，自动截断过长的历史。

        策略：
        1. system 消息始终保留（不计入截断预算）
        2. 从最新消息开始向前保留，直到 Token 预算用尽
        3. 返回 [system..., ...recent_history]

        Parameters
        ----------
        system_prompts : list[str]
            系统提示词列表（每个作为独立 system 消息）
        history : list[dict]
            对话历史 [{"role": "user"|"assistant", "content": "..."}]

        Returns
        -------
        list[dict]
            截断后的完整消息列表
        """
        # 构建 system 消息
        system_msgs = [{"role": "system", "content": p} for p in system_prompts]
        system_tokens = LLMClient.estimate_messages_tokens(system_msgs)

        available = self.max_context_tokens - system_tokens - self.reserved_tokens

        # 从最新到最旧保留历史消息
        kept: list[dict] = []
        used = 0

        for msg in reversed(history):
            msg_tokens = LLMClient.estimate_tokens(msg.get("content", "")) + 4
            if used + msg_tokens > available:
                break
            kept.insert(0, msg)
            used += msg_tokens

        if len(kept) < len(history):
            logger.info(
                "上下文窗口截断: %d/%d 条消息保留 (tokens: %d/%d)",
                len(kept), len(history), used, available,
            )

        return system_msgs + kept

    @staticmethod
    def estimate_total_tokens(messages: list[dict]) -> int:
        """估算消息列表的总 Token 消耗。"""
        return LLMClient.estimate_messages_tokens(messages)

    # ------------------------------------------------------------------
    # 删除
    # ------------------------------------------------------------------
    @staticmethod
    def delete_history(task_id: int) -> int:
        """删除指定任务的全部对话历史，返回删除条数。"""
        db = SessionLocal()
        try:
            count = (
                db.query(Conversation)
                .filter(Conversation.task_id == task_id)
                .delete()
            )
            db.commit()
            logger.info("已删除任务 %d 的 %d 条对话记录", task_id, count)
            return count
        finally:
            db.close()
