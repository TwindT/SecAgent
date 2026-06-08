from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="SecAgent API", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {"message": "SecAgent API is running"}

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

@app.post("/api/tasks")
async def create_task():
    return {"task_id": "task-001", "status": "pending"}