"""
Celery 任务队列测试脚本

使用方式:
  本地（无 Redis）:  python tests/test_celery_queue.py --local
  远程（有 Redis）:  python tests/test_celery_queue.py
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

HAS_REDIS = "--local" not in sys.argv


def test_imports():
    print("=" * 60)
    print("测试 1: 模块导入")
    print("=" * 60)
    from app.celery_app import celery_app
    print(f"  Celery app: {celery_app.main}")
    print(f"  Broker:     {celery_app.conf.broker_url}")
    print(f"  Concurrency: {celery_app.conf.worker_concurrency}")
    from app.services.task_queue import (
        run_analysis_task, submit_task, load_steps, get_queue_status,
    )
    print(f"  Task name:  {run_analysis_task.name}")
    print("  [OK] 模块导入成功")


def test_step_storage():
    print()
    print("=" * 60)
    print("测试 2: 步骤存储/加载")
    print("=" * 60)
    from app.services.task_queue import _save_step, load_steps, _get_db
    from app.models.database import AnalysisStep

    test_id = 99999
    _save_step(test_id, {"step_num": 1, "type": "thought", "data": {"content": "test", "tool_calls_requested": []}})
    _save_step(test_id, {"step_num": 1, "type": "action", "data": {"results": [{"name": "t", "ok": True}]}})
    steps = load_steps(test_id)
    print(f"  写入 2 步，加载到 {len(steps)} 步")
    assert len(steps) == 2, f"Expected 2, got {len(steps)}"

    db = _get_db()
    db.query(AnalysisStep).filter(AnalysisStep.task_id == test_id).delete()
    db.commit()
    db.close()
    print("  [OK] 步骤存储/加载正常")


def test_queue_status():
    print()
    print("=" * 60)
    print("测试 3: 队列状态查询")
    print("=" * 60)
    from app.services.task_queue import get_queue_status
    status = get_queue_status()
    print(f"  Pending:   {status['pending_count']}")
    print(f"  Analyzing: {status['analyzing_count']}")
    print(f"  Max concurrent: {status['max_concurrent']}")
    print("  [OK] 队列状态正常")


def test_celery_submit():
    print()
    print("=" * 60)
    if HAS_REDIS:
        print("测试 4: Celery 任务提交与执行")
    else:
        print("测试 4: 跳过 (--local 模式)")
    print("=" * 60)
    if not HAS_REDIS:
        print("  在远程服务器上运行时不加 --local 即可完整测试")
        return

    import os as _os
    from app.models.database import init_db, SessionLocal, Task as TaskModel
    from app.services.task_queue import submit_task, run_analysis_task

    init_db(_os.getenv("DATABASE_URL", "sqlite:///./app.db"))
    db = SessionLocal()
    try:
        t = TaskModel(type="vulnerability_detection", status="pending",
                      input_content="print('hello')")
        db.add(t)
        db.commit()
        db.refresh(t)
        tid = t.id
        print(f"  创建测试任务 DB id={tid}")
    finally:
        db.close()

    try:
        celery_id = submit_task(task_id=tid, task_type="vulnerability_detection",
                                input_content="print('hello')")
        print(f"  Celery task ID: {celery_id}")
        print("  [OK] 任务已入队")
        print("  等待执行 (最多 120s)...")
        result = run_analysis_task.AsyncResult(celery_id)
        waited = 0
        while not result.ready() and waited < 120:
            time.sleep(2)
            waited += 2
            if waited % 10 == 0:
                print(f"    已等待 {waited}s...")
        if result.ready():
            if result.successful():
                print(f"  [OK] 任务执行成功: {result.get()}")
            else:
                print(f"  [FAIL] 任务执行失败: {result.result}")
        else:
            print("  [WARN] 任务超时，请检查 Worker 日志")
    except Exception as e:
        print(f"  [FAIL] Celery 提交失败: {e}")
        print("  请确认: 1) Redis 运行中  2) Celery Worker 运行中")


if __name__ == "__main__":
    test_imports()
    test_step_storage()
    test_queue_status()
    test_celery_submit()
    print()
    print("=" * 60)
    print("测试完成")
    print("=" * 60)
