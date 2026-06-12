"""任务管理 API 路由"""

import json
import logging

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy.orm import Session

from ..models import (
    get_db,
    Task,
    TaskType,
    TaskStatus,
    CreateTaskRequest,
    CreateTaskResponse,
    TaskResponse,
    TaskListResponse,
    SendMessageRequest,
    SendMessageResponse,
    TaskTypeEnum,
    TaskStatusEnum,
    AnalysisStepResponse,
)
from ..report import generate_pdf, render_markdown
from ..services.conversation import ConversationManager
from ..services.task_queue import submit_task, load_steps, get_queue_status as _get_queue_status
from ..agent.llm import LLMClient

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/tasks", tags=["tasks"])

# 全局对话管理器实例
conv_manager = ConversationManager()


# ============================================================================
# 任务 CRUD
# ============================================================================

@router.post("", response_model=CreateTaskResponse)
def create_task(req: CreateTaskRequest, db: Session = Depends(get_db)):
    """创建分析任务，存入数据库，通过任务队列异步执行，返回 task_id。"""
    task = Task(
        type=TaskType(req.type.value),
        status=TaskStatus.PENDING,
        input_path=req.input_path,
        input_content=req.input_content,
    )
    db.add(task)
    db.commit()
    db.refresh(task)

    # 通过 Celery + Redis 任务队列提交（worker 并发数 3）
    submit_task(
        task_id=task.id,
        task_type=req.type.value,
        input_content=req.input_content or "",
    )

    return CreateTaskResponse(task_id=task.id)


@router.get("", response_model=TaskListResponse)
def list_tasks(
    page: int = Query(1, ge=1, description="页码"),
    page_size: int = Query(20, ge=1, le=100, description="每页条数"),
    type: Optional[TaskTypeEnum] = Query(None, description="按任务类型筛选"),
    status: Optional[TaskStatusEnum] = Query(None, description="按任务状态筛选"),
    db: Session = Depends(get_db),
):
    """查询历史任务列表，支持分页和按类型/状态筛选。按创建时间倒序排列。"""
    query = db.query(Task)

    if type:
        query = query.filter(Task.type == TaskType(type.value))
    if status:
        query = query.filter(Task.status == TaskStatus(status.value))

    total = query.count()
    tasks = (
        query.order_by(Task.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return TaskListResponse(total=total, tasks=tasks)


# ============================================================================
# 队列状态（必须在 /{task_id} 之前注册，避免 "queue" 被当作 task_id）
# ============================================================================

@router.get("/queue/status")
def queue_status_endpoint():
    """查询任务队列状态：等待中、分析中任务数、最大并发数。"""
    return _get_queue_status()


# ============================================================================
# 任务详情 + 分析步骤
# ============================================================================

@router.get("/{task_id}", response_model=TaskResponse)
def get_task(task_id: int, db: Session = Depends(get_db)):
    """查询单个任务的状态、结果和已完成的分析步骤。"""
    task = db.query(Task).filter(Task.id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail=f"任务 {task_id} 不存在")

    # 加载分析步骤（实时反映当前进度）
    if task.analysis_steps is None:
        task.analysis_steps = []
    return task


@router.get("/{task_id}/steps", response_model=list[AnalysisStepResponse])
def get_task_steps(task_id: int, db: Session = Depends(get_db)):
    """查询指定任务的所有分析步骤（Thought → Action → Observe 链）。"""
    task = db.query(Task).filter(Task.id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail=f"任务 {task_id} 不存在")

    # 从 DB 加载持久化的步骤
    steps = load_steps(task_id)

    # 如果 DB 中无记录，尝试从 result_json 中的 steps 提取（兼容旧任务）
    if not steps and task.result_json:
        try:
            result = json.loads(task.result_json)
            raw_steps = result.get("steps", [])
            for s in raw_steps:
                data = s.get("data", {})
                step_num = s.get("step_num", 0)
                step_type = s.get("type", "")
                step = {
                    "id": 0,
                    "task_id": task_id,
                    "step_num": step_num,
                    "created_at": data.get("timestamp", ""),
                }
                if step_type == "thought":
                    step["thought"] = json.dumps(data, ensure_ascii=False)[:2000]
                elif step_type == "action":
                    step["action"] = json.dumps(data, ensure_ascii=False)[:2000]
                else:
                    step["observation"] = json.dumps(data, ensure_ascii=False)[:2000]
                steps.append(step)
        except (json.JSONDecodeError, TypeError, KeyError):
            pass

    return steps


# ============================================================================
# 对话追问
# ============================================================================

@router.post("/{task_id}/chat", response_model=SendMessageResponse)
def chat_with_task(
    task_id: int,
    req: SendMessageRequest,
    db: Session = Depends(get_db),
):
    """对已完成的分析任务发送追问，Agent 基于分析上下文回复。

    使用 ConversationManager 管理对话历史和上下文窗口。
    """
    task = db.query(Task).filter(Task.id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail=f"任务 {task_id} 不存在")

    # 1. 存储用户消息
    conv_manager.add_message(task_id, "user", req.message)

    # 2. 加载历史对话
    history = conv_manager.load_history_as_messages(task_id)

    # 3. 构建 system prompts
    system_prompts = [
        (
            "你是一名资深安全分析专家。用户正在对一份已完成的安全分析报告进行追问。"
            "请基于分析结果简洁专业地回答用户的问题。"
        ),
    ]
    if task.result_json:
        system_prompts.append(
            f"以下是已完成的分析结果供参考：\n{task.result_json}"
        )

    # 4. 上下文窗口管理：截断过长历史后构建最终消息列表
    messages = conv_manager.build_context_messages(system_prompts, history)

    logger.info(
        "对话上下文构建完成: task_id=%d system_msgs=%d history_msgs=%d total_tokens=%d",
        task_id, len(system_prompts), len(history),
        conv_manager.estimate_total_tokens(messages),
    )

    # 5. 调用 LLM
    llm = LLMClient()
    result = llm.chat(messages=messages)
    reply_text = result.get("content") or result.get("error", "无法生成回复")

    # 6. 存储助手回复
    conv_manager.add_message(task_id, "assistant", reply_text)

    return SendMessageResponse(reply=reply_text, task_id=task_id)


# ============================================================================
# 报告导出
# ============================================================================

@router.get("/{task_id}/report/pdf")
def download_report_pdf(task_id: int, db: Session = Depends(get_db)):
    """生成并下载任务的安全分析 PDF 报告（Markdown→HTML→PDF）。"""
    task = db.query(Task).filter(Task.id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail=f"任务 {task_id} 不存在")

    pdf_bytes = generate_pdf(task)

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=secagent-report-{task_id}.pdf"},
    )


@router.get("/{task_id}/report/md")
def download_report_md(task_id: int, db: Session = Depends(get_db)):
    """生成并下载任务的安全分析 Markdown 报告。"""
    task = db.query(Task).filter(Task.id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail=f"任务 {task_id} 不存在")

    md_text = render_markdown(task)

    return Response(
        content=md_text,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename=secagent-report-{task_id}.md"},
    )
