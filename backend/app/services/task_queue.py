"""
任务队列管理 — Celery + Redis 实现异步任务队列。

设计:
- Celery 作为任务队列，Redis 作为 broker 和 result backend
- worker_concurrency=3 控制最多 3 个任务同时执行
- 任务状态机: pending → analyzing → done / failed
- 分析步骤自动写入数据库，支持实时查询
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Optional

from ..celery_app import celery_app
from ..agent.llm import LLMClient
from ..services.task_runner import run_task_sync
from ..services.cleanup import cleanup_task_files

logger = logging.getLogger(__name__)

# 最大并发数（由 Celery worker_concurrency 控制）
MAX_CONCURRENT_TASKS = int(os.getenv("CELERY_CONCURRENCY", "3"))

# ---------------------------------------------------------------------------
# 任务状态机
# ---------------------------------------------------------------------------
# pending ──▶ analyzing ──▶ done
#                         └──▶ failed
# ---------------------------------------------------------------------------

VALID_TRANSITIONS: dict[str, set[str]] = {
    "pending": {"analyzing"},
    "analyzing": {"done", "failed"},
    "done": set(),
    "failed": set(),
}


def _get_db():
    """延迟获取数据库会话（避免模块级 import 时 DB 未初始化）。"""
    from ..models.database import SessionLocal, init_db
    if SessionLocal is None:
        database_url = os.getenv("DATABASE_URL", "sqlite:///./app.db")
        init_db(database_url)
    from ..models.database import SessionLocal as SL
    return SL()


# ============================================================================
# Celery 任务定义
# ============================================================================

@celery_app.task(bind=True, name="secagent.analyze_task", max_retries=1)
def run_analysis_task(self, task_id: int, task_type: str, input_content: str) -> dict:
    """Celery 任务：执行安全分析。

    由 API 层通过 .delay() 提交到 Redis 队列，
    Celery worker 自动拉取并在 concurrency=3 的限制下并发执行。

    Parameters
    ----------
    task_id : int
        数据库中的任务 ID
    task_type : str
        "vulnerability_detection" 或 "malware_analysis"
    input_content : str
        分析输入内容

    Returns
    -------
    dict
        分析结果摘要
    """
    from ..models.database import Task as TaskModel

    task = None
    db = _get_db()
    try:
        # ---- pending → analyzing ----
        task = db.query(TaskModel).filter(TaskModel.id == task_id).first()
        if not task:
            return {"error": f"任务 {task_id} 不存在"}

        _transition_status(task_id, "analyzing", db=db)

        # ---- 执行分析 ----
        def on_step(step: dict) -> None:
            _save_step(task_id, step)

        llm = LLMClient()
        result = run_task_sync(
            task_id=str(task_id),
            task_type=task_type,
            input_content=input_content or "",
            llm=llm,
            on_step_callback=on_step,
        )

        # ---- analyzing → done ----
        task = db.query(TaskModel).filter(TaskModel.id == task_id).first()
        if task:
            task.status = _task_status("done")
            task.result_json = json.dumps(result, ensure_ascii=False, default=str)
            task.updated_at = datetime.now(timezone.utc)
            db.commit()
        logger.info("Celery 任务 %d 执行完成", task_id)

        return {
            "task_id": task_id,
            "status": "done",
            "total_steps": result.get("total_steps", 0),
            "elapsed_seconds": result.get("elapsed_seconds", 0),
        }

    except Exception as e:
        logger.exception("Celery 任务 %d 执行失败", task_id)
        _transition_status(
            task_id, "failed",
            error=json.dumps({"error": str(e)}, ensure_ascii=False),
            db=db,
        )
        # 不自动重试（max_retries=1 表示不重试，直接标记失败）
        return {"task_id": task_id, "status": "failed", "error": str(e)}

    finally:
        try:
            input_path = task.input_path if task else None
            cleanup_task_files(input_path=input_path)
        except Exception as e:
            logger.warning("临时文件清理异常: %s", e)
        db.close()


# ============================================================================
# 任务提交
# ============================================================================

def submit_task(task_id: int, task_type: str, input_content: str) -> str:
    """提交分析任务到 Celery 队列。

    非阻塞：立即返回 Celery task ID。

    Parameters
    ----------
    task_id : int
        数据库中的任务 ID
    task_type : str
        "vulnerability_detection" 或 "malware_analysis"
    input_content : str
        分析输入内容

    Returns
    -------
    str
        Celery 任务 UUID
    """
    async_result = run_analysis_task.delay(
        task_id=task_id,
        task_type=task_type,
        input_content=input_content,
    )
    logger.info(
        "Celery 任务已入队: db_id=%d celery_id=%s type=%s",
        task_id, async_result.id, task_type,
    )
    return async_result.id


# ============================================================================
# 队列状态查询
# ============================================================================

def get_queue_status() -> dict:
    """查询当前队列状态。"""
    from ..models.database import Task as TaskModel

    db = _get_db()
    try:
        pending = (
            db.query(TaskModel)
            .filter(TaskModel.status == _task_status("pending"))
            .count()
        )
        analyzing = (
            db.query(TaskModel)
            .filter(TaskModel.status == _task_status("analyzing"))
            .count()
        )

        # Celery 活跃/保留任务数（timeout=2s 防止阻塞）
        active_count = 0
        reserved_count = 0
        try:
            inspect = celery_app.control.inspect(timeout=2.0)
            active = inspect.active()
            if active:
                active_count = sum(len(v) for v in active.values())
            reserved = inspect.reserved()
            if reserved:
                reserved_count = sum(len(v) for v in reserved.values())
        except Exception:
            pass  # Redis 不可用或超时时降级

        return {
            "pending_count": pending,
            "analyzing_count": analyzing,
            "celery_active": active_count,
            "celery_reserved": reserved_count,
            "max_concurrent": MAX_CONCURRENT_TASKS,
        }
    finally:
        db.close()


# ============================================================================
# 步骤持久化
# ============================================================================

def _save_step(task_id: int, step: dict) -> None:
    """将单个分析步骤写入数据库。"""
    from ..models.database import AnalysisStep

    db = _get_db()
    try:
        step_num = step.get("step_num", 0)
        step_type = step.get("type", "")
        data = step.get("data", {})

        thought = None
        action = None
        observation = None

        if step_type == "thought":
            thought = json.dumps(data, ensure_ascii=False)[:2000]
        elif step_type == "action":
            action = json.dumps(data, ensure_ascii=False)[:2000]
        elif step_type == "observation":
            observation = json.dumps(data, ensure_ascii=False)[:2000]
        else:
            observation = json.dumps(data, ensure_ascii=False)[:2000]

        record = AnalysisStep(
            task_id=task_id,
            step_num=step_num,
            thought=thought,
            action=action,
            observation=observation,
        )
        db.add(record)
        db.commit()
    except Exception as e:
        logger.warning("保存分析步骤失败: task=%d step=%d error=%s", task_id, step.get("step_num"), e)
    finally:
        db.close()


def load_steps(task_id: int) -> list[dict]:
    """加载指定任务的已存储分析步骤。"""
    from ..models.database import AnalysisStep

    db = _get_db()
    try:
        records = (
            db.query(AnalysisStep)
            .filter(AnalysisStep.task_id == task_id)
            .order_by(AnalysisStep.step_num.asc())
            .all()
        )
        steps: list[dict] = []
        for r in records:
            steps.append({
                "id": r.id,
                "task_id": r.task_id,
                "step_num": r.step_num,
                "thought": r.thought,
                "action": r.action,
                "observation": r.observation,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            })
        return steps
    finally:
        db.close()


# ============================================================================
# 辅助函数
# ============================================================================

def _transition_status(
    task_id: int,
    new_status: str,
    error: Optional[str] = None,
    db=None,
) -> None:
    """执行状态转换并写入数据库。"""
    from ..models.database import Task as TaskModel

    own_db = False
    if db is None:
        db = _get_db()
        own_db = True
    try:
        task = db.query(TaskModel).filter(TaskModel.id == task_id).first()
        if not task:
            return

        old_status = task.status.value if hasattr(task.status, 'value') else str(task.status)
        allowed = VALID_TRANSITIONS.get(old_status, set())
        if new_status not in allowed and allowed:
            logger.warning("非法状态转换: task=%d %s → %s", task_id, old_status, new_status)

        task.status = _task_status(new_status)
        task.updated_at = datetime.now(timezone.utc)
        if error and new_status == "failed":
            task.result_json = error
        db.commit()
        logger.info("任务 %d 状态: %s → %s", task_id, old_status, new_status)
    finally:
        if own_db:
            db.close()


def _task_status(status: str):
    """字符串 → TaskStatus 枚举转换。"""
    from ..models.database import TaskStatus as TS
    mapping = {
        "pending": TS.PENDING,
        "analyzing": TS.ANALYZING,
        "done": TS.DONE,
        "failed": TS.FAILED,
    }
    return mapping.get(status, TS.PENDING)
