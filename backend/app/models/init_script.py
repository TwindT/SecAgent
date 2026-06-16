import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.database import init_db, get_db, Task, TaskType, TaskStatus
from datetime import datetime, timezone

def test_database():
    print("Initializing database...")
    init_db("sqlite:///./test_secagent.db")
    
    print("Creating test task...")
    db = next(get_db())
    
    test_task = Task(
        type=TaskType.VULNERABILITY_DETECTION,
        status=TaskStatus.PENDING,
        input_content="print('Hello, SecAgent!')",
        created_at=datetime.now(timezone.utc)
    )
    
    db.add(test_task)
    db.commit()
    
    print("Querying test task...")
    tasks = db.query(Task).all()
    print(f"Total tasks: {len(tasks)}")
    
    for task in tasks:
        print(f"Task ID: {task.id}, Type: {task.type}, Status: {task.status}")
    
    print("Database test completed successfully!")
    
    db.close()

if __name__ == "__main__":
    test_database()