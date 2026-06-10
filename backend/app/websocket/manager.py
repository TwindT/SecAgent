"""
WebSocket 连接管理器 — ConnectionManager

管理按 task_id 分组的 WebSocket 连接，支持：
- 多连接（同一任务可被多个客户端订阅）
- 心跳检测（30s 间隔，连续 2 次无响应断开）
- 消息历史（客户端断线重连后回放已推送的步骤）
- 任务结束时自动关闭连接
"""

import asyncio
import json
import logging
import time
from typing import Dict, Set

from fastapi import WebSocket
from starlette.websockets import WebSocketState

logger = logging.getLogger(__name__)

# 心跳间隔（秒）
HEARTBEAT_INTERVAL = 30
# 连续心跳失败次数阈值
MAX_HEARTBEAT_MISSES = 2
# done/error 后延迟关闭连接（秒，给客户端时间接收最后一条消息）
CLOSE_DELAY = 3


class ConnectionManager:
    """WebSocket 连接管理器（单例模式）。"""

    _instance: "ConnectionManager | None" = None

    def __new__(cls) -> "ConnectionManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self) -> None:
        if self._initialized:
            return
        self._initialized = True
        self._connections: Dict[str, Set[WebSocket]] = {}
        self._heartbeat_tasks: Dict[WebSocket, asyncio.Task] = {}
        self._heartbeat_misses: Dict[WebSocket, int] = {}
        # 任务消息历史（支持断线重连回放）
        self._task_history: Dict[str, list[dict]] = {}

    # ------------------------------------------------------------------
    # 连接管理
    # ------------------------------------------------------------------

    async def connect(self, task_id: str, websocket: WebSocket) -> None:
        """接受 WebSocket 连接并注册到 task_id 分组。

        如果该任务已有历史消息（之前已开始分析），
        会在连接确认前先回放所有历史步骤。
        """
        await websocket.accept()
        self._connections.setdefault(task_id, set()).add(websocket)
        self._heartbeat_misses[websocket] = 0
        logger.info(
            "WebSocket 已连接: task_id=%s, 当前该任务连接数=%d",
            task_id, len(self._connections[task_id]),
        )

        # 回放已有历史消息
        history = self._task_history.get(task_id, [])
        if history:
            logger.info("回放 %d 条历史消息给 task_id=%s", len(history), task_id)
            for msg in history:
                try:
                    await websocket.send_text(
                        json.dumps(msg, ensure_ascii=False)
                    )
                except Exception:
                    break  # 客户端可能已断开

        # 启动心跳任务
        self._heartbeat_tasks[websocket] = asyncio.create_task(
            self._heartbeat_loop(websocket, task_id)
        )

    def disconnect(self, task_id: str, websocket: WebSocket) -> None:
        """移除连接并清理心跳任务。"""
        if task_id in self._connections:
            self._connections[task_id].discard(websocket)
            if not self._connections[task_id]:
                del self._connections[task_id]
        task = self._heartbeat_tasks.pop(websocket, None)
        if task:
            task.cancel()
        self._heartbeat_misses.pop(websocket, None)
        logger.info("WebSocket 已断开: task_id=%s", task_id)

    # ------------------------------------------------------------------
    # 消息推送与历史
    # ------------------------------------------------------------------

    async def send_message(self, task_id: str, message: dict) -> None:
        """向订阅该任务的所有连接推送 JSON 消息，并存入历史。

        当消息 type 为 "done" 或 "error" 时，推送后自动调度关闭连接。
        """
        # 存入历史（即使当前无连接，供后续重连回放）
        self._task_history.setdefault(task_id, []).append(message)

        payload = json.dumps(message, ensure_ascii=False)
        dead: list[WebSocket] = []
        for ws in list(self._connections.get(task_id, set())):
            try:
                if ws.client_state == WebSocketState.CONNECTED:
                    await ws.send_text(payload)
                else:
                    dead.append(ws)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(task_id, ws)

        # done / error → 延迟后自动关闭连接
        if message.get("type") in ("done", "error"):
            asyncio.create_task(self._close_after_delay(task_id))

    async def _close_after_delay(self, task_id: str) -> None:
        """延迟关闭，确保客户端有时间接收最后一条消息。"""
        await asyncio.sleep(CLOSE_DELAY)
        await self.close_task_connections(task_id)

    async def close_task_connections(self, task_id: str) -> None:
        """任务结束时关闭该任务的所有 WebSocket 连接并清理历史。"""
        # 关闭所有连接
        for ws in list(self._connections.get(task_id, set())):
            try:
                if ws.client_state == WebSocketState.CONNECTED:
                    await ws.close(code=1000, reason="task completed")
            except Exception:
                pass
            self._heartbeat_tasks.pop(ws, None)
            self._heartbeat_misses.pop(ws, None)
        self._connections.pop(task_id, None)
        # 清理历史
        self._task_history.pop(task_id, None)
        logger.info("任务连接已关闭并清理: task_id=%s", task_id)

    # ------------------------------------------------------------------
    # 心跳检测
    # ------------------------------------------------------------------

    async def _heartbeat_loop(self, websocket: WebSocket, task_id: str) -> None:
        """定期发送心跳 ping，检测连接是否存活。

        每 HEARTBEAT_INTERVAL 秒发送一次 ping。
        发送失败 → 累计失败次数 → 达到 MAX_HEARTBEAT_MISSES 后断开。
        """
        try:
            while True:
                await asyncio.sleep(HEARTBEAT_INTERVAL)
                if websocket.client_state != WebSocketState.CONNECTED:
                    break
                try:
                    await websocket.send_text('{"type":"ping"}')
                    # 发送成功 → 重置失败计数
                    self._heartbeat_misses[websocket] = 0
                except Exception:
                    misses = self._heartbeat_misses.get(websocket, 0) + 1
                    self._heartbeat_misses[websocket] = misses
                    logger.warning(
                        "心跳发送失败: task_id=%s misses=%d/%d",
                        task_id, misses, MAX_HEARTBEAT_MISSES,
                    )
                    if misses >= MAX_HEARTBEAT_MISSES:
                        break
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.warning("心跳循环异常: %s", e)
        finally:
            self.disconnect(task_id, websocket)
            try:
                if websocket.client_state == WebSocketState.CONNECTED:
                    await websocket.close(code=1001, reason="heartbeat timeout")
            except Exception:
                pass

    def record_pong(self, websocket: WebSocket) -> None:
        """客户端回复了 pong，重置心跳失败计数。"""
        self._heartbeat_misses[websocket] = 0

    # ------------------------------------------------------------------
    # 查询
    # ------------------------------------------------------------------

    def get_connection_count(self, task_id: str) -> int:
        """获取某任务的当前连接数。"""
        return len(self._connections.get(task_id, set()))

    @property
    def total_connections(self) -> int:
        return sum(len(s) for s in self._connections.values())


# 全局单例
manager = ConnectionManager()
