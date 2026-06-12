"""
Celery 应用配置 — Redis 作为 broker 和 result backend。

在 docker-compose 环境中：
  REDIS_URL=redis://redis:6379/0

本地开发时可通过 .env 设置 REDIS_URL。
"""

import os
import logging

from celery import Celery
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

celery_app = Celery(
    "secagent",
    broker=REDIS_URL,
    backend=REDIS_URL,
)

celery_app.conf.update(
    # 任务序列化
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],

    # 并发控制
    worker_concurrency=3,               # 最多 3 个任务同时执行
    worker_prefetch_multiplier=1,       # 公平调度：每次只取 1 个任务

    # 超时
    task_soft_time_limit=300,           # 软超时 5 分钟
    task_time_limit=360,                # 硬超时 6 分钟

    # 结果过期
    result_expires=3600,                # 结果保留 1 小时

    # 时区
    timezone="UTC",
    enable_utc=True,

    # 重试
    task_acks_late=True,                # 任务完成后才确认（防丢失）
    task_reject_on_worker_lost=True,    # Worker 丢失时重新分配
)

logger.info("Celery app configured: broker=%s concurrency=%d", REDIS_URL, 3)

# 确保任务模块被导入（Celery worker 启动时会通过 -A app.celery_app 加载）
try:
    from .services import task_queue  # noqa: F401
except ImportError as e:
    logger.warning("任务模块导入失败: %s — Celery 任务可能未注册", e)
