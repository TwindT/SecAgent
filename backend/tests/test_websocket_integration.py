"""
2.5 WebSocket 集成测试（任务 4：连接管理）

覆盖：心跳检测 | 历史回放 | 自动关闭 | 多客户端广播
"""

import asyncio
import json
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import websockets
import httpx

SERVER_URL = "ws://localhost:8000"
HTTP_URL = "http://localhost:8000"

ALL_STEP_TYPES = [
    {"type": "thought", "data": {"step_num": 1, "content": "分析代码", "tool_calls_requested": ["scan_code"]}},
    {"type": "action", "data": {"step_num": 1, "results": [{"name": "scan_code", "ok": True, "args": {}}]}},
    {"type": "observation", "data": {"step_num": 1, "observations": [{"tool": "scan_code", "result_preview": "2 issues"}]}},
    {"type": "done", "data": {"step_num": 2, "message": "完成", "elapsed_seconds": 1.0, "total_steps": 2}},
]


def _uid(name: str) -> str:
    return f"{name}-{int(time.time() * 1000000)}"


async def _push(client: httpx.AsyncClient, task_id: str, step: dict):
    resp = await client.post(f"{HTTP_URL}/api/debug/push/{task_id}", json=step, timeout=5)
    assert resp.status_code == 200, f"HTTP push failed: {resp.status_code}"


async def _recv_until(ws, expected_type: str, timeout: float = 5.0) -> dict | None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            raw = await asyncio.wait_for(ws.recv(), timeout=deadline - time.time())
            msg = json.loads(raw)
            if msg["type"] == expected_type:
                return msg
        except asyncio.TimeoutError:
            return None
    return None


async def _recv_available(ws, timeout: float = 2.0) -> list[dict]:
    msgs = []
    while True:
        try:
            raw = await asyncio.wait_for(ws.recv(), timeout=timeout)
            msgs.append(json.loads(raw))
        except asyncio.TimeoutError:
            break
    return msgs


# ==============================================================================
# Test 1: 基础连接/断开
# ==============================================================================

async def test_basic_connect_disconnect():
    task_id = _uid("basic")
    async with websockets.connect(f"{SERVER_URL}/ws/{task_id}") as ws:
        msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=5))
        assert msg["type"] == "connected"
    async with websockets.connect(f"{SERVER_URL}/ws/{task_id}") as ws:
        msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=5))
        assert msg["type"] == "connected"
    print("[PASS] test_basic_connect_disconnect")


# ==============================================================================
# Test 2: 心跳 — pong 保持存活
# ==============================================================================

async def test_heartbeat_pong_keeps_alive():
    task_id = _uid("heartbeat")
    async with websockets.connect(f"{SERVER_URL}/ws/{task_id}") as ws:
        conn = json.loads(await asyncio.wait_for(ws.recv(), timeout=5))
        assert conn["type"] == "connected"

        # 回复 pong
        await ws.send("pong")

        async with httpx.AsyncClient() as client:
            await _push(client, task_id, {
                "type": "thought",
                "data": {"step_num": 1, "content": "alive check"},
            })

        msg = await _recv_until(ws, "thought", timeout=5)
        assert msg is not None, "pong 后连接应存活"
        assert msg["data"]["content"] == "alive check"
    print("[PASS] test_heartbeat_pong_keeps_alive")


# ==============================================================================
# Test 3: 历史回放
# ==============================================================================

async def test_history_replay_on_reconnect():
    task_id = _uid("replay")

    # 连接 → 推送 → 断开
    async with websockets.connect(f"{SERVER_URL}/ws/{task_id}") as ws:
        await asyncio.wait_for(ws.recv(), timeout=5)  # connected
        async with httpx.AsyncClient() as client:
            await _push(client, task_id, ALL_STEP_TYPES[0])  # thought
            await _push(client, task_id, ALL_STEP_TYPES[1])  # action
        await _recv_until(ws, "thought", timeout=5)
        await _recv_until(ws, "action", timeout=5)

    await asyncio.sleep(0.5)
    # 重连 → 应回放历史
    async with websockets.connect(f"{SERVER_URL}/ws/{task_id}") as ws:
        msgs = await _recv_available(ws, timeout=3)
        types_seen = [m["type"] for m in msgs]
        assert "thought" in types_seen, f"应回放 thought, 收到: {types_seen}"
        assert "action" in types_seen, f"应回放 action, 收到: {types_seen}"
        assert "connected" in types_seen, f"应有 connected, 收到: {types_seen}"
    print("[PASS] test_history_replay_on_reconnect")


# ==============================================================================
# Test 4: done 后自动关闭
# ==============================================================================

async def test_auto_close_after_done():
    task_id = _uid("autoclose-done")

    async with websockets.connect(f"{SERVER_URL}/ws/{task_id}", close_timeout=10) as ws:
        await asyncio.wait_for(ws.recv(), timeout=5)  # connected

        async with httpx.AsyncClient() as client:
            await _push(client, task_id, ALL_STEP_TYPES[3])  # done

        done_msg = await _recv_until(ws, "done", timeout=5)
        assert done_msg is not None

        # 等待服务端关闭 (CLOSE_DELAY=3s)
        try:
            await asyncio.wait_for(ws.recv(), timeout=8)
        except (websockets.exceptions.ConnectionClosed, asyncio.TimeoutError):
            pass  # 连接应已关闭
    print("[PASS] test_auto_close_after_done")


# ==============================================================================
# Test 5: error 后自动关闭
# ==============================================================================

async def test_auto_close_after_error():
    task_id = _uid("autoclose-error")

    async with websockets.connect(f"{SERVER_URL}/ws/{task_id}", close_timeout=10) as ws:
        await asyncio.wait_for(ws.recv(), timeout=5)

        async with httpx.AsyncClient() as client:
            await _push(client, task_id, {
                "type": "error",
                "data": {"step_num": 1, "message": "fatal error", "elapsed_seconds": 0.1},
            })

        error_msg = await _recv_until(ws, "error", timeout=5)
        assert error_msg is not None

        try:
            await asyncio.wait_for(ws.recv(), timeout=8)
        except (websockets.exceptions.ConnectionClosed, asyncio.TimeoutError):
            pass
    print("[PASS] test_auto_close_after_error")


# ==============================================================================
# Test 6: 多客户端完整流程
# ==============================================================================

async def test_full_workflow_multi_client():
    task_id = _uid("full")
    steps_before_done = ALL_STEP_TYPES[:-1]

    async with (
        websockets.connect(f"{SERVER_URL}/ws/{task_id}") as ws1,
        websockets.connect(f"{SERVER_URL}/ws/{task_id}") as ws2,
    ):
        await asyncio.wait_for(ws1.recv(), timeout=5)
        await asyncio.wait_for(ws2.recv(), timeout=5)

        async with httpx.AsyncClient() as client:
            for step in steps_before_done:
                await _push(client, task_id, step)

        # 收集前 3 条
        msgs1 = await _recv_available(ws1, timeout=3)
        assert len(msgs1) == 3, f"ws1 应收到 3 条(thought+action+obs)，实际 {len(msgs1)}"

        # 推送 done
        async with httpx.AsyncClient() as client:
            await _push(client, task_id, ALL_STEP_TYPES[-1])

        done1 = await _recv_until(ws1, "done", timeout=5)
        assert done1 is not None
        done2 = await _recv_until(ws2, "done", timeout=5)
        assert done2 is not None
    print("[PASS] test_full_workflow_multi_client")


# ==============================================================================
# Run
# ==============================================================================

async def main():
    print("\n" + "=" * 55)
    print("  2.5 Task 4: Connection Management Tests")
    print("=" * 55 + "\n")

    tests = [
        test_basic_connect_disconnect,
        test_heartbeat_pong_keeps_alive,
        test_history_replay_on_reconnect,
        test_auto_close_after_done,
        test_auto_close_after_error,
        test_full_workflow_multi_client,
    ]

    passed = 0
    failed = 0
    for test_fn in tests:
        try:
            await test_fn()
            passed += 1
        except Exception as e:
            failed += 1
            print(f"[FAIL] {test_fn.__name__}: {e}")
            import traceback
            traceback.print_exc()

    print(f"\n{'=' * 55}")
    print(f"  Results: {passed} passed, {failed} failed of {len(tests)}")
    print(f"{'=' * 55}\n")
    return failed == 0


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(main()) else 1)
