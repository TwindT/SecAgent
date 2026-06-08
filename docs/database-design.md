# SecAgent 数据库设计文档

## 数据库概述

- **数据库类型**: SQLite（原型系统）
- **数据库文件**: `secagent.db`
- **ORM 框架**: SQLAlchemy 2.0
- **验证框架**: Pydantic v2

---

## ER 图

```
┌─────────────────────────────────────────────────────────────────────┐
│                           task                                       │
│  ┌──────────┬─────────────────────────────────────────────────┐     │
│  │ id (PK)  │ Integer, 自增主键                               │     │
│  │ type     │ Enum: vulnerability_detection/malware_analysis│     │
│  │ status   │ Enum: pending/analyzing/done/failed            │     │
│  │ input_path│ String(500), 上传文件的路径                      │     │
│  │ input_content│ Text, 直接粘贴的代码/文本内容                 │     │
│  │ result_json│ Text, 完整分析结果(JSON格式)                    │     │
│  │ created_at│ DateTime, 创建时间                              │     │
│  │ updated_at│ DateTime, 最后更新时间                           │     │
│  └──────────┴─────────────────────────────────────────────────┘     │
│                                    │                                │
│           ┌────────────────────────┴────────────────────────┐        │
│           │                    1:N                        │        │
│           ▼                                                 ▼        │
│  ┌─────────────────────┐                    ┌─────────────────────┐│
│  │   analysis_step     │                    │    conversation      ││
│  │  ┌────────────────┐ │                    │  ┌────────────────┐ ││
│  │  │ id (PK)       │ │                    │  │ id (PK)        │ ││
│  │  │ task_id (FK)  │ │                    │  │ task_id (FK)   │ ││
│  │  │ step_num      │ │                    │  │ role           │ ││
│  │  │ thought       │ │                    │  │ content        │ ││
│  │  │ action        │ │                    │  │ created_at      │ ││
│  │  │ observation   │ │                    │  └────────────────┘ ││
│  │  │ created_at    │ │                    └─────────────────────┘│
│  │  └────────────────┘ │                                                │
│  └─────────────────────┘                                                │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 表结构详细说明

### 1. task 表（分析任务表）

| 字段名 | 类型 | 约束 | 说明 |
|--------|------|------|------|
| id | INTEGER | PRIMARY KEY, AUTOINCREMENT | 任务唯一标识 |
| type | ENUM | NOT NULL | 任务类型：`vulnerability_detection`（漏洞检测）或 `malware_analysis`（恶意分析） |
| status | ENUM | NOT NULL, DEFAULT 'pending' | 任务状态：`pending`（等待中）、`analyzing`（分析中）、`done`（已完成）、`failed`（失败） |
| input_path | VARCHAR(500) | NULLABLE | 上传文件的存储路径 |
| input_content | TEXT | NULLABLE | 直接粘贴的代码/文本内容 |
| result_json | TEXT | NULLABLE | 完整的分析结果，以 JSON 格式存储 |
| created_at | DATETIME | NOT NULL, DEFAULT NOW | 任务创建时间 |
| updated_at | DATETIME | NOT NULL, DEFAULT NOW | 任务最后更新时间 |

**索引**：
- 主键索引：`id`
- 任务状态索引：`status`（用于查询待处理任务）
- 创建时间索引：`created_at`（用于历史记录排序）

---

### 2. analysis_step 表（分析步骤表）

| 字段名 | 类型 | 约束 | 说明 |
|--------|------|------|------|
| id | INTEGER | PRIMARY KEY, AUTOINCREMENT | 步骤唯一标识 |
| task_id | INTEGER | FOREIGN KEY → task.id, NOT NULL | 所属任务 ID |
| step_num | INTEGER | NOT NULL | 步骤序号（从 1 开始） |
| thought | TEXT | NULLABLE | Agent 的思考内容（Reasoning） |
| action | TEXT | NULLABLE | Agent 采取的动作（调用工具） |
| observation | TEXT | NULLABLE | 工具执行结果（观察结果） |
| created_at | DATETIME | NOT NULL, DEFAULT NOW | 步骤创建时间 |

**索引**：
- 主键索引：`id`
- 外键索引：`task_id`（用于查询某任务的所有步骤）

**级联操作**：
- 当 task 删除时，自动删除所有关联的 analysis_step 记录

---

### 3. conversation 表（对话历史表）

| 字段名 | 类型 | 约束 | 说明 |
|--------|------|------|------|
| id | INTEGER | PRIMARY KEY, AUTOINCREMENT | 对话唯一标识 |
| task_id | INTEGER | FOREIGN KEY → task.id, NOT NULL | 所属任务 ID |
| role | ENUM | NOT NULL | 角色：`user`（用户）或 `assistant`（Agent） |
| content | TEXT | NOT NULL | 对话内容 |
| created_at | DATETIME | NOT NULL, DEFAULT NOW | 对话创建时间 |

**索引**：
- 主键索引：`id`
- 外键索引：`task_id`（用于查询某任务的所有对话）
- 创建时间索引：`created_at`（用于按时间排序）

**级联操作**：
- 当 task 删除时，自动删除所有关联的 conversation 记录

---

## 代码使用示例

### 1. 初始化数据库

```python
from backend.app.models import init_db, get_db

# 初始化（创建所有表）
init_db("sqlite:///./secagent.db")
```

### 2. 创建任务

```python
from backend.app.models import Task, TaskType, TaskStatus, get_db

db = next(get_db())
task = Task(
    type=TaskType.VULNERABILITY_DETECTION,
    status=TaskStatus.PENDING,
    input_content="print('Hello, SecAgent!')"
)
db.add(task)
db.commit()
db.refresh(task)
print(f"Created task with id: {task.id}")
```

### 3. 添加分析步骤

```python
from backend.app.models import AnalysisStep

step = AnalysisStep(
    task_id=task.id,
    step_num=1,
    thought="我应该先进行静态代码扫描",
    action="scan_code(code='...', language='python')",
    observation="发现 3 个可疑点"
)
db.add(step)
db.commit()
```

### 4. 添加对话记录

```python
from backend.app.models import Conversation, ConversationRole

# 用户消息
user_msg = Conversation(
    task_id=task.id,
    role=ConversationRole.USER,
    content="帮我检查这段代码有什么漏洞"
)
db.add(user_msg)

# Agent 回复
assistant_msg = Conversation(
    task_id=task.id,
    role=ConversationRole.ASSISTANT,
    content="我已经完成了代码分析，发现了 2 个安全问题..."
)
db.add(assistant_msg)
db.commit()
```

### 5. 查询任务及其关联数据

```python
from backend.app.models import Task

# 查询任务
task = db.query(Task).filter(Task.id == 1).first()

# 打印任务信息
print(f"Task Type: {task.type}")
print(f"Status: {task.status}")
print(f"Created: {task.created_at}")

# 打印分析步骤
for step in task.analysis_steps:
    print(f"Step {step.step_num}: {step.thought}")

# 打印对话历史
for msg in task.conversations:
    print(f"[{msg.role}] {msg.content}")
```

---

## 数据模型文件

| 文件 | 说明 |
|------|------|
| `backend/app/models/database.py` | SQLAlchemy 模型定义（ORM 表结构） |
| `backend/app/models/schemas.py` | Pydantic 模型定义（API 请求/响应验证） |
| `backend/app/models/__init__.py` | 模块导出 |

---

## 注意事项

1. **JSON 存储**：`result_json` 字段用于存储完整的分析结果，便于前端直接渲染
2. **时间戳**：所有表都有 `created_at` 字段，`task` 和 `analysis_step` 还有 `updated_at` 用于跟踪更新
3. **级联删除**：删除任务时会自动删除关联的分析步骤和对话记录
4. **枚举存储**：SQLite 不原生支持枚举，SQLAlchemy 会自动将其存储为字符串

---

> **文档版本**: v1.0
> **编写日期**: 2026-06-08
> **负责人**: 成员 C
