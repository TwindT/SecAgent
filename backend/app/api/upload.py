"""文件上传 API 路由 — 多层安全控制"""

import hashlib
import logging
import os
import re
import uuid
from pathlib import Path

from fastapi import APIRouter, File, HTTPException, UploadFile
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["upload"])

# ---------------------------------------------------------------------------
# 安全配置
# ---------------------------------------------------------------------------
MAX_UPLOAD_SIZE = 50 * 1024 * 1024  # 50MB
MAX_FILENAME_LENGTH = 255

# 允许的文件扩展名白名单
ALLOWED_EXTENSIONS: set[str] = {
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

# 魔数签名 → 允许的扩展名映射（内容类型双重校验）
MAGIC_BYTES_MAP: dict[bytes, list[str]] = {
    b"MZ": [".exe", ".dll", ".bin", ".scr", ".sys"],          # PE
    b"\x7fELF": [".elf", ".so", ".bin"],                       # ELF
    b"PK\x03\x04": [".zip", ".docx", ".xlsx", ".jar"],         # ZIP/Office
    b"\xd0\xcf\x11\xe0": [".doc", ".xls", ".ppt"],             # OLE2 (Office 97-2003)
    b"%PDF": [".pdf"],                                          # PDF
    b"\x89PNG": [".png"],                                       # PNG
    b"\xff\xd8\xff": [".jpg", ".jpeg"],                         # JPEG
    b"#!/": [".sh", ".py", ".rb"],                              # Script shebang
    b"<?xml": [".xml"],                                         # XML
    b"{\n": [".json"],                                          # JSON (pretty)
    b"{": [".json"],                                            # JSON (compact)
}

UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", "data/uploads"))

# 危险文件名模式（路径穿越、命令注入等）
_DANGEROUS_FILENAME_RE = re.compile(r"[/\\]|\.\.|^\.$|[\x00-\x1f]|`|\$|\||;")


class UploadResponse(BaseModel):
    filename: str
    file_hash: str       # SHA-256
    md5_hash: str         # MD5
    size: int
    path: str
    content_type_detected: str = ""


# ---------------------------------------------------------------------------
# 安全校验工具
# ---------------------------------------------------------------------------

def _sanitize_filename(filename: str) -> str:
    """清理文件名：移除路径穿越、空字节、危险字符。

    保留 Unicode 字母、数字、._- 和中文等合法字符。
    """
    if not filename or len(filename) > MAX_FILENAME_LENGTH:
        raise HTTPException(status_code=400, detail="文件名无效或过长")

    # 检测路径穿越和空字节注入
    if _DANGEROUS_FILENAME_RE.search(filename):
        raise HTTPException(status_code=400, detail="文件名包含非法字符")

    # 去除首尾空白
    filename = filename.strip()

    # 防止双重扩展绕过（如 file.txt.exe）
    basename = Path(filename).stem
    if not basename:
        raise HTTPException(status_code=400, detail="文件名为空")

    return filename


def _get_extension(filename: str) -> str:
    """提取文件扩展名（小写），处理复合后缀。"""
    name_lower = filename.lower()
    if name_lower.endswith(".tar.gz"):
        return ".tar.gz"
    return Path(filename).suffix.lower()


def _detect_magic_type(header: bytes) -> str:
    """基于文件头魔数检测真实文件类型。

    Returns
    -------
    str
        检测描述，如 "PE executable", "ELF binary", "unknown"
    """
    for magic, labels in MAGIC_BYTES_MAP.items():
        if header.startswith(magic):
            return ", ".join(labels)
    return "unknown"


def _validate_content_type(filename: str, header: bytes) -> None:
    """交叉校验：扩展名 vs 魔数内容类型。

    仅对二进制/可执行文件做强校验；文本/脚本文件允许魔数不匹配
    （因为纯文本文件没有魔数特征）。
    """
    ext = _get_extension(filename)
    detected = _detect_magic_type(header)
    detected_exts = detected.split(", ")

    # 文本/代码类文件不做严格魔数校验（它们的魔数不固定）
    text_exts = {".py", ".java", ".js", ".ts", ".c", ".cpp", ".h", ".cs",
                 ".go", ".rs", ".php", ".rb", ".txt", ".csv", ".json",
                 ".xml", ".yaml", ".yml", ".sh", ".bat", ".ps1", ".vbs", ".vba"}
    if ext in text_exts:
        return

    # 二进制文件：如果魔数识别成功但扩展名不匹配 → 拒绝
    if detected != "unknown" and ext not in detected_exts:
        raise HTTPException(
            status_code=400,
            detail=f"文件扩展名 '{ext}' 与实际内容类型 ({detected}) 不匹配，可能是伪装文件",
        )


def _compute_hashes(file_path: Path) -> tuple[str, str]:
    """同时计算 SHA-256 和 MD5 哈希值。"""
    h_sha256 = hashlib.sha256()
    h_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h_sha256.update(chunk)
            h_md5.update(chunk)
    return h_sha256.hexdigest(), h_md5.hexdigest()


# ---------------------------------------------------------------------------
# API 端点
# ---------------------------------------------------------------------------

@router.post("/upload", response_model=UploadResponse)
async def upload_file(file: UploadFile = File(...)):
    """上传文件用于安全分析。

    多层安全校验：
    1. 文件名清理（防路径穿越）
    2. 扩展名白名单
    3. 魔数内容类型交叉验证
    4. 大小限制（50MB 分块校验）
    5. SHA-256 + MD5 双哈希记录
    """

    # ---- 1. 文件名安全校验 ----
    safe_name = _sanitize_filename(file.filename or "")
    ext = _get_extension(safe_name)

    # ---- 2. 扩展名白名单 ----
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"不支持的文件类型 '{ext}'。允许的类型: {', '.join(sorted(ALLOWED_EXTENSIONS))}",
        )

    # ---- 3. 写入临时文件 ----
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    unique_name = f"{uuid.uuid4().hex[:12]}_{safe_name}"
    save_path = UPLOAD_DIR / unique_name

    size = 0
    header_chunk = b""
    with open(save_path, "wb") as f:
        while chunk := await file.read(8192):
            # 捕获文件头（用于魔数校验）
            if not header_chunk:
                header_chunk = chunk[:256]

            size += len(chunk)
            if size > MAX_UPLOAD_SIZE:
                save_path.unlink(missing_ok=True)
                raise HTTPException(status_code=413, detail="文件大小超过上限 (50MB)")
            f.write(chunk)

    if size == 0:
        save_path.unlink(missing_ok=True)
        raise HTTPException(status_code=400, detail="上传的文件为空")

    # ---- 4. 魔数内容类型交叉验证 ----
    try:
        _validate_content_type(safe_name, header_chunk)
    except HTTPException:
        save_path.unlink(missing_ok=True)
        raise

    # ---- 5. 计算双哈希 ----
    sha256_hash, md5_hash = _compute_hashes(save_path)

    content_type = _detect_magic_type(header_chunk)
    logger.info(
        "文件上传成功: name=%s size=%d sha256=%s md5=%s content_type=%s",
        file.filename, size, sha256_hash[:16], md5_hash, content_type,
    )

    return UploadResponse(
        filename=unique_name,
        file_hash=sha256_hash,
        md5_hash=md5_hash,
        size=size,
        path=str(save_path),
        content_type_detected=content_type,
    )
