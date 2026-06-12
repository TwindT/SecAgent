"""任务管理 API 路由"""

import json
import logging
import threading

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy.orm import Session

from ..models import (
    get_db,
    Task,
    TaskType,
    TaskStatus,
    Conversation,
    ConversationRole,
    CreateTaskRequest,
    CreateTaskResponse,
    TaskResponse,
    TaskListResponse,
    SendMessageRequest,
    SendMessageResponse,
    TaskTypeEnum,
    TaskStatusEnum,
    AnalysisStepResponse,
    ConversationResponse,
)
from ..report import generate_pdf, render_markdown
from ..services import run_task_sync
from ..agent.llm import LLMClient

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/tasks", tags=["tasks"])


def _run_analysis(task_id: int, task_type: str, input_content: str):
    """在后台线程中执行分析任务并更新数据库状态。"""
    from ..models.database import SessionLocal, Task as TaskModel, TaskStatus as TS

    db = SessionLocal()
    try:
        task = db.query(TaskModel).filter(TaskModel.id == task_id).first()
        if not task:
            return

        task.status = TS.ANALYZING
        db.commit()

        llm = LLMClient()
        result = run_task_sync(
            task_id=str(task_id),
            task_type=task_type,
            input_content=input_content or "",
            llm=llm,
        )

        task.status = TS.DONE
        task.result_json = json.dumps(result, ensure_ascii=False, default=str)
        db.commit()
        logger.info("任务 %d 执行完成", task_id)

    except Exception as e:
        logger.exception("任务 %d 执行失败", task_id)
        try:
            task = db.query(TaskModel).filter(TaskModel.id == task_id).first()
            if task:
                task.status = TS.FAILED
                task.result_json = json.dumps({"error": str(e)}, ensure_ascii=False)
                db.commit()
        except Exception:
            pass
    finally:
        db.close()


@router.post("", response_model=CreateTaskResponse)
def create_task(req: CreateTaskRequest, db: Session = Depends(get_db)):
    """创建分析任务，存入数据库，启动后台分析，返回 task_id。"""
    task = Task(
        type=TaskType(req.type.value),
        status=TaskStatus.PENDING,
        input_path=req.input_path,
        input_content=req.input_content,
    )
    db.add(task)
    db.commit()
    db.refresh(task)

    # 启动后台分析线程
    thread = threading.Thread(
        target=_run_analysis,
        args=(task.id, req.type.value, req.input_content or ""),
        daemon=True,
    )
    thread.start()

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


@router.get("/{task_id}", response_model=TaskResponse)
def get_task(task_id: int, db: Session = Depends(get_db)):
    """查询单个任务的状态、结果和分析步骤。"""
    task = db.query(Task).filter(Task.id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail=f"任务 {task_id} 不存在")
    return task


@router.post("/{task_id}/chat", response_model=SendMessageResponse)
def chat_with_task(
    task_id: int,
    req: SendMessageRequest,
    db: Session = Depends(get_db),
):
    """对已完成的分析任务发送追问，Agent 基于分析上下文回复。"""
    task = db.query(Task).filter(Task.id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail=f"任务 {task_id} 不存在")

    # 存储用户消息
    user_msg = Conversation(
        task_id=task_id,
        role=ConversationRole.USER,
        content=req.message,
    )
    db.add(user_msg)
    db.commit()

    # 构建对话上下文
    history = (
        db.query(Conversation)
        .filter(Conversation.task_id == task_id)
        .order_by(Conversation.created_at.asc())
        .all()
    )

    system_prompt = (
        "你是一名资深安全分析专家。用户正在对一份已完成的安全分析报告进行追问。"
        "请基于分析结果简洁专业地回答用户的问题。"
    )

    messages = [{"role": "system", "content": system_prompt}]

    if task.result_json:
        messages.append({
            "role": "system",
            "content": f"以下是已完成的分析结果供参考：\n{task.result_json}",
        })

    for msg in history:
        role = "user" if msg.role == ConversationRole.USER else "assistant"
        messages.append({"role": role, "content": msg.content})

    # 调用 LLM
    llm = LLMClient()
    result = llm.chat(messages=messages)
    reply_text = result.get("content") or result.get("error", "无法生成回复")

    # 存储助手回复
    assistant_msg = Conversation(
        task_id=task_id,
        role=ConversationRole.ASSISTANT,
        content=reply_text,
    )
    db.add(assistant_msg)
    db.commit()

    return SendMessageResponse(reply=reply_text, task_id=task_id)


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
