import logging
import os

from dotenv import load_dotenv
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .api import tasks_router, upload_router
from .middleware import RateLimitMiddleware
from .models import init_db
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


@app.on_event("startup")
def on_startup():
    database_url = os.getenv("DATABASE_URL", "sqlite:///./app.db")
    init_db(database_url)
    logger.info("数据库已初始化: %s", database_url)


@app.get("/")
async def root():
    return {"message": "SecAgent API is running"}


@app.get("/health")
async def health_check():
    return {"status": "healthy"}


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
            "task_id": task_id,
            "message": "已订阅任务分析过程，等待分析开始...",
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