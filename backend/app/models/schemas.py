from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, List
from enum import Enum

class TaskTypeEnum(str, Enum):
    VULNERABILITY_DETECTION = "vulnerability_detection"
    MALWARE_ANALYSIS = "malware_analysis"

class TaskStatusEnum(str, Enum):
    PENDING = "pending"
    ANALYZING = "analyzing"
    DONE = "done"
    FAILED = "failed"

class ConversationRoleEnum(str, Enum):
    USER = "user"
    ASSISTANT = "assistant"

class CreateTaskRequest(BaseModel):
    type: TaskTypeEnum
    name: Optional[str] = None
    input_content: Optional[str] = None
    input_path: Optional[str] = None

    class Config:
        from_attributes = True

class CreateTaskResponse(BaseModel):
    task_id: int
    message: str = "Task created successfully"

class AnalysisStepResponse(BaseModel):
    id: int
    task_id: int
    step_num: int
    thought: Optional[str]
    action: Optional[str]
    observation: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True

class TaskResponse(BaseModel):
    id: int
    name: Optional[str] = None
    type: str
    status: str
    input_path: Optional[str]
    input_content: Optional[str]
    result_json: Optional[str]
    analysis_steps: Optional[List[AnalysisStepResponse]] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class ConversationResponse(BaseModel):
    id: int
    task_id: int
    role: str
    content: str
    created_at: datetime
    
    class Config:
        from_attributes = True

class SendMessageRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=5000)

class SendMessageResponse(BaseModel):
    reply: str
    task_id: int

class TaskListResponse(BaseModel):
    total: int
    tasks: List[TaskResponse]

class WebSocketMessage(BaseModel):
    type: str
    data: dict = {}
