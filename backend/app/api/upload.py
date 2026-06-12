"""文件上传 API 路由"""

import hashlib
import logging
import os
import uuid
from pathlib import Path

from fastapi import APIRouter, File, HTTPException, UploadFile
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["upload"])

# 上传文件大小上限 50MB
MAX_UPLOAD_SIZE = 50 * 1024 * 1024

# 允许的文件扩展名白名单
ALLOWED_EXTENSIONS = {
    # 代码文件
    ".py", ".java", ".js", ".ts", ".c", ".cpp", ".h", ".cs", ".go", ".rs", ".php", ".rb",
    # 脚本
    ".ps1", ".sh", ".bat", ".vbs", ".vba",
    # Office 文档
    ".doc", ".docm", ".docx", ".xls", ".xlsm", ".xlsx",
    # 文本/数据
    ".txt", ".csv", ".json", ".xml", ".yaml", ".yml",
    # 可执行文件
    ".exe", ".dll", ".so", ".elf", ".bin",
    # 压缩文件
    ".zip", ".tar.gz", ".rar",
}

# 上传临时目录
UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", "data/uploads"))


class UploadResponse(BaseModel):
    filename: str
    file_hash: str
    size: int
    path: str


def _compute_sha256(file_path: Path) -> str:
    """计算文件的 SHA-256 哈希值。"""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _get_extension(filename: str) -> str:
    """提取文件扩展名（小写），处理 .tar.gz 等复合后缀。"""
    name_lower = filename.lower()
    if name_lower.endswith(".tar.gz"):
        return ".tar.gz"
    return Path(filename).suffix.lower()


@router.post("/upload", response_model=UploadResponse)
async def upload_file(file: UploadFile = File(...)):
    """上传文件用于安全分析。类型白名单校验 + 大小限制 + 临时存储。"""

    # 1. 检查文件名
    if not file.filename:
        raise HTTPException(status_code=400, detail="文件名为空")

    ext = _get_extension(file.filename)
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"不支持的文件类型 '{ext}'。允许的类型: {', '.join(sorted(ALLOWED_EXTENSIONS))}",
        )

    # 2. 读取文件内容（分块读取以控制大小）
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    unique_name = f"{uuid.uuid4().hex[:12]}_{file.filename}"
    save_path = UPLOAD_DIR / unique_name

    size = 0
    with open(save_path, "wb") as f:
        while chunk := await file.read(8192):
            size += len(chunk)
            if size > MAX_UPLOAD_SIZE:
                save_path.unlink(missing_ok=True)
                raise HTTPException(status_code=413, detail="文件大小超过上限 (50MB)")
            f.write(chunk)

    if size == 0:
        save_path.unlink(missing_ok=True)
        raise HTTPException(status_code=400, detail="上传的文件为空")

    # 3. 计算哈希
    file_hash = _compute_sha256(save_path)

    logger.info("文件上传成功: name=%s size=%d hash=%s", file.filename, size, file_hash)

    return UploadResponse(
        filename=unique_name,
        file_hash=file_hash,
        size=size,
        path=str(save_path),
    )
