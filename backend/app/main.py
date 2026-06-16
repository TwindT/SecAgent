import logging
import os
import json
import asyncio

from dotenv import load_dotenv
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .api import tasks_router, upload_router
from .middleware import RateLimitMiddleware
from .models import init_db, get_db
from .websocket import manager

load_dotenv()

logger = logging.getLogger(__name__)

# CORS 允许的来源，通过环境变量可配置，默认全允许（开发模式）
ALLOWED_ORIGINS = os.getenv("CORS_ORIGINS", "*").split(",")

app = FastAPI(title="SecAgent API", version="1.0")

# CORS 中间件
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 速率限制中间件（每 IP 每分钟最多 60 次请求），跳过 WebSocket
app.add_middleware(
    RateLimitMiddleware,
    max_requests=int(os.getenv("RATE_LIMIT_MAX", "60")),
    window=int(os.getenv("RATE_LIMIT_WINDOW", "60")),
)

app.include_router(tasks_router)
app.include_router(upload_router)


# ---------------------------------------------------------------------------
# Redis Pub/Sub 订阅 — 接收 Celery worker 发布的 WebSocket 消息
# ---------------------------------------------------------------------------

_redis_subscriber_task = None


async def _redis_subscriber():
    """后台任务：订阅 Redis ws:* 频道，将消息转发给 WebSocket 客户端。

    Celery worker 运行在独立进程中，无法直接访问 FastAPI 的
    ConnectionManager。因此 worker 通过 Redis Pub/Sub 发布消息到
    ``ws:{task_id}`` 频道，本订阅者接收后调用 manager.send_message()
    推送给前端 WebSocket 客户端。
    """
    import redis.asyncio as aioredis

    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    r = aioredis.from_url(redis_url)
    pubsub = r.pubsub()

    try:
        # 订阅所有 ws:* 频道
        await pubsub.psubscribe("ws:*")
        logger.info("Redis Pub/Sub 订阅已启动: ws:*")

        async for message in pubsub.listen():
            if message["type"] not in ("pmessage",):
                continue

            channel = message["channel"]
            if isinstance(channel, bytes):
                channel = channel.decode("utf-8")

            # 从频道名提取 task_id: "ws:{task_id}" → task_id
            task_id = channel.replace("ws:", "", 1)

            data = message["data"]
            if isinstance(data, bytes):
                data = data.decode("utf-8")

            try:
                msg = json.loads(data)
            except (json.JSONDecodeError, TypeError):
                logger.warning("Redis 消息解析失败: channel=%s", channel)
                continue

            # 转发给 WebSocket ConnectionManager
            try:
                await manager.send_message(task_id, msg)
            except Exception as e:
                logger.warning("WebSocket 转发失败: task_id=%s error=%s", task_id, e)

    except asyncio.CancelledError:
        logger.info("Redis Pub/Sub 订阅已取消")
    except Exception as e:
        logger.error("Redis Pub/Sub 订阅异常: %s", e)
    finally:
        await pubsub.punsubscribe("ws:*")
        await pubsub.aclose()
        await r.aclose()


@app.on_event("startup")
async def on_startup():
    database_url = os.getenv("DATABASE_URL", "sqlite:///./app.db")
    init_db(database_url)
    logger.info("数据库已初始化: %s", database_url)

    # 清理上次运行残留的临时文件
    from .services.cleanup import ensure_clean_dirs
    ensure_clean_dirs()
    logger.info("临时目录已就绪")

    # 启动 Redis Pub/Sub 订阅后台任务
    global _redis_subscriber_task
    _redis_subscriber_task = asyncio.create_task(_redis_subscriber())
    logger.info("Redis Pub/Sub 订阅后台任务已启动")


@app.on_event("shutdown")
async def on_shutdown():
    """关闭时取消 Redis 订阅后台任务。"""
    global _redis_subscriber_task
    if _redis_subscriber_task:
        _redis_subscriber_task.cancel()
        try:
            await _redis_subscriber_task
        except asyncio.CancelledError:
            pass
        logger.info("Redis Pub/Sub 订阅后台任务已停止")


@app.get("/")
async def root():
    return {"message": "SecAgent API is running"}


@app.get("/health")
async def health_check():
    return {"status": "healthy"}


@app.get("/api/stats")
def get_stats(db: Session = Depends(get_db)):
    """获取仪表盘统计数据：总任务数、今日任务数、高危数、平均耗时、近期任务等。"""
    from .models import Task, TaskStatus, TaskType, TaskResponse
    from .models.database import AnalysisStep, Conversation
    from datetime import datetime, timedelta, timezone
    from sqlalchemy import func
    from sqlalchemy.orm import load_only, noload

    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

    # 总任务数
    total_tasks = db.query(func.count(Task.id)).scalar() or 0

    # 今日任务数
    today_tasks = db.query(func.count(Task.id)).filter(Task.created_at >= today_start).scalar() or 0

    # 高危任务数（从 result_json 中提取 severity/confidence.level）
    all_done_tasks = db.query(Task).filter(Task.status == TaskStatus.DONE).all()
    high_severity_count = 0
    durations = []
    for t in all_done_tasks:
        if t.result_json:
            try:
                import json
                result = json.loads(t.result_json)
                # 优先从 confidence.level 获取，其次从顶层 severity 获取
                sev = result.get("confidence", {}).get("level") or result.get("severity", "")
                if sev == "high":
                    high_severity_count += 1
            except (json.JSONDecodeError, AttributeError):
                pass
        if t.created_at and t.updated_at:
            diff = (t.updated_at - t.created_at).total_seconds()
            if diff > 0:
                durations.append(diff)

    # 平均耗时
    avg_duration = f"{sum(durations) / len(durations):.0f}s" if durations else "—"

    # 近期任务（最近5个，不加载关联数据）
    recent_tasks = (
        db.query(Task)
        .options(noload(Task.analysis_steps), noload(Task.conversations))
        .order_by(Task.created_at.desc())
        .limit(5)
        .all()
    )

    # 按类型统计
    tasks_by_type = []
    for t_type in [TaskType.VULNERABILITY_DETECTION, TaskType.MALWARE_ANALYSIS]:
        count = db.query(func.count(Task.id)).filter(Task.type == t_type).scalar() or 0
        tasks_by_type.append({"type": t_type.value, "count": count})

    # 按严重等级统计
    severity_counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
    for t in all_done_tasks:
        if t.result_json:
            try:
                import json
                result = json.loads(t.result_json)
                # 优先从 confidence.level 获取，其次从顶层 severity 获取
                sev = result.get("confidence", {}).get("level") or result.get("severity", "info")
                if sev in severity_counts:
                    severity_counts[sev] += 1
                else:
                    severity_counts["info"] += 1
            except (json.JSONDecodeError, AttributeError):
                pass
    tasks_by_severity = [{"severity": k, "count": v} for k, v in severity_counts.items()]

    # 按天统计（最近7天）
    tasks_by_day = []
    for i in range(6, -1, -1):
        day = (now - timedelta(days=i)).strftime("%Y-%m-%d")
        day_start = datetime.strptime(day, "%Y-%m-%d")
        day_end = day_start + timedelta(days=1)
        count = db.query(func.count(Task.id)).filter(
            Task.created_at >= day_start, Task.created_at < day_end
        ).scalar() or 0
        tasks_by_day.append({"date": day, "count": count})

    return {
        "total_tasks": total_tasks,
        "today_tasks": today_tasks,
        "high_severity_tasks": high_severity_count,
        "avg_duration": avg_duration,
        "recent_tasks": recent_tasks,
        "tasks_by_type": tasks_by_type,
        "tasks_by_severity": tasks_by_severity,
        "tasks_by_day": tasks_by_day,
    }


# ---------------------------------------------------------------------------
# WebSocket 端点 — 实时推送 Agent 分析过程
# ---------------------------------------------------------------------------

@app.websocket("/ws/{task_id}")
async def websocket_endpoint(websocket: WebSocket, task_id: str):
    """WebSocket 端点：订阅指定任务的实时分析步骤。

    连接后服务端会：
    1. 回放该任务已有的历史步骤（断线重连支持）
    2. 发送 connected 确认消息
    3. 持续推送新的分析步骤
    4. 每 30s 发送心跳 ping（客户端可回复 pong 表示存活）
    5. done/error 后 3 秒自动关闭连接（任务结束）

    推送消息格式：
        {"type": "thought|action|observation|done|error", "data": {...}}
    """
    await manager.connect(task_id, websocket)
    try:
        await websocket.send_json({
            "type": "connected",
            "data": {
                "task_id": task_id,
                "message": "已订阅任务分析过程，等待分析开始...",
            },
        })
        while True:
            try:
                data = await websocket.receive_text()
                if data == "pong" or data.startswith('{"type":"pong"'):
                    manager.record_pong(websocket)
                    continue
                logger.debug("收到客户端消息: task_id=%s msg=%s", task_id, data[:100])
            except WebSocketDisconnect:
                break
            except Exception as e:
                logger.warning("接收消息异常: %s", e)
                break
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error("WebSocket 异常: task_id=%s error=%s", task_id, e)
    finally:
        manager.disconnect(task_id, websocket)


# ---------------------------------------------------------------------------
# 调试端点：模拟引擎推送（开发/测试用，后续由真实任务 API 替代）
# ---------------------------------------------------------------------------

class PushMessageRequest(BaseModel):
    type: str
    data: dict = {}


@app.post("/api/debug/push/{task_id}")
async def debug_push(task_id: str, msg: PushMessageRequest):
    """向指定任务的 WebSocket 客户端推送一条测试消息。

    即使没有客户端连接也会存入历史（供重连回放）。
    """
    await manager.send_message(task_id, {"type": msg.type, "data": msg.data})
    return {"ok": True, "connections": manager.get_connection_count(task_id)}