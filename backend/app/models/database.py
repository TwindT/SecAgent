from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, ForeignKey, Enum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
from enum import Enum as PyEnum

Base = declarative_base()

class TaskType(PyEnum):
    VULNERABILITY_DETECTION = "vulnerability_detection"
    MALWARE_ANALYSIS = "malware_analysis"

class TaskStatus(PyEnum):
    PENDING = "pending"
    ANALYZING = "analyzing"
    DONE = "done"
    FAILED = "failed"

class ConversationRole(PyEnum):
    USER = "user"
    ASSISTANT = "assistant"

class Task(Base):
    __tablename__ = "task"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    type = Column(Enum(TaskType, values_callable=lambda x: [e.value for e in x]), nullable=False)
    status = Column(Enum(TaskStatus, values_callable=lambda x: [e.value for e in x]), nullable=False, default=TaskStatus.PENDING)
    input_path = Column(String(500))
    input_content = Column(Text)
    result_json = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    analysis_steps = relationship("AnalysisStep", back_populates="task", cascade="all, delete-orphan")
    conversations = relationship("Conversation", back_populates="task", cascade="all, delete-orphan")

class AnalysisStep(Base):
    __tablename__ = "analysis_step"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    task_id = Column(Integer, ForeignKey("task.id"), nullable=False)
    step_num = Column(Integer, nullable=False)
    thought = Column(Text)
    action = Column(Text)
    observation = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    task = relationship("Task", back_populates="analysis_steps")

class Conversation(Base):
    __tablename__ = "conversation"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    task_id = Column(Integer, ForeignKey("task.id"), nullable=False)
    role = Column(Enum(ConversationRole, values_callable=lambda x: [e.value for e in x]), nullable=False)
    content = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    task = relationship("Task", back_populates="conversations")

engine = None
SessionLocal = None

def init_db(database_url: str = "sqlite:///./secagent.db"):
    global engine, SessionLocal
    engine = create_engine(
        database_url,
        connect_args={"check_same_thread": False} if "sqlite" in database_url else {}
    )
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)

def get_db():
    global SessionLocal
    if SessionLocal is None:
        init_db()
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()