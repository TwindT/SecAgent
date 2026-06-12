"""
临时文件清理模块 — 分析完成后自动删除临时文件。

清理策略:
1. 任务级清理 — 分析完成后立即删除该任务关联的上传文件和临时文件
2. 定时兜底清理 — 删除超过保留期限的残留文件（防止异常中断导致的文件堆积）
"""

import logging
import os
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# 默认配置
DEFAULT_UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", "data/uploads"))
DEFAULT_TEMP_DIR = Path(os.getenv("TEMP_DIR", "data/temp"))
DEFAULT_MAX_AGE_HOURS = 24  # 残留文件最大保留时间


def cleanup_task_files(
    input_path: Optional[str] = None,
    upload_dir: Optional[Path] = None,
) -> dict:
    """分析完成后删除任务关联的临时文件。

    根据任务的 input_path 定位并删除上传文件，
    同时清理分析过程中可能产生的临时文件。

    Parameters
    ----------
    input_path : str | None
        任务关联的文件路径（来自 task.input_path 或 UploadResponse.path）
    upload_dir : Path | None
        上传目录，默认使用环境变量 UPLOAD_DIR

    Returns
    -------
    dict
        {"deleted": [str, ...], "errors": [str, ...]}
    """
    upload_dir = upload_dir or DEFAULT_UPLOAD_DIR
    deleted: list[str] = []
    errors: list[str] = []

    # ---- 1. 删除任务关联的上传文件 ----
    if input_path:
        target = Path(input_path)
        if target.exists():
            try:
                target.unlink()
                deleted.append(str(target))
                logger.info("已删除上传文件: %s", target)
            except OSError as e:
                errors.append(f"删除 {target} 失败: {e}")
                logger.warning("删除上传文件失败: %s", e)
        else:
            logger.debug("上传文件已不存在，跳过: %s", target)

    # ---- 2. 清理任务专属临时文件（按文件名匹配 task 关联的 unique 前缀） ----
    # 注意：不盲目清空整个 temp 目录，避免并发任务的竞态条件
    if input_path:
        temp_dir = DEFAULT_TEMP_DIR
        path_obj = Path(input_path)
        # 提取上传文件的 unique 前缀（格式: <12hex>_<original_name>）
        stem_prefix = path_obj.name[:12] if len(path_obj.name) >= 12 else ""
        if temp_dir.exists() and stem_prefix:
            for f in temp_dir.iterdir():
                if f.is_file() and f.name.startswith(stem_prefix):
                    try:
                        f.unlink()
                        deleted.append(str(f))
                        logger.debug("已删除临时文件: %s", f)
                    except OSError as e:
                        errors.append(f"删除 {f} 失败: {e}")

    if deleted:
        logger.info("任务文件清理完成: 删除 %d 个文件", len(deleted))

    return {"deleted": deleted, "errors": errors}


def cleanup_stale_files(
    upload_dir: Optional[Path] = None,
    temp_dir: Optional[Path] = None,
    max_age_hours: int = DEFAULT_MAX_AGE_HOURS,
) -> dict:
    """清理超过保留期限的残留文件（兜底机制）。

    用于处理异常中断导致的上传/临时文件堆积。
    可在启动时或定时任务中调用。

    Parameters
    ----------
    upload_dir : Path | None
        上传目录
    temp_dir : Path | None
        临时目录
    max_age_hours : int
        文件最大保留时间（小时），超过则删除

    Returns
    -------
    dict
        {"deleted_count": int, "freed_bytes": int, "errors": [str, ...]}
    """
    upload_dir = upload_dir or DEFAULT_UPLOAD_DIR
    temp_dir = temp_dir or DEFAULT_TEMP_DIR
    now = time.time()
    max_age_seconds = max_age_hours * 3600

    deleted_count = 0
    freed_bytes = 0
    errors: list[str] = []

    for directory in [upload_dir, temp_dir]:
        if not directory.exists():
            continue

        for f in directory.iterdir():
            if not f.is_file():
                continue
            try:
                age = now - f.stat().st_mtime
                if age > max_age_seconds:
                    size = f.stat().st_size
                    f.unlink()
                    deleted_count += 1
                    freed_bytes += size
                    logger.info("清理残留文件: %s (age=%.1fh size=%d)", f, age / 3600, size)
            except OSError as e:
                errors.append(f"清理 {f} 失败: {e}")

    if deleted_count:
        logger.info(
            "残留文件清理完成: 删除 %d 个文件, 释放 %d 字节",
            deleted_count, freed_bytes,
        )

    return {
        "deleted_count": deleted_count,
        "freed_bytes": freed_bytes,
        "errors": errors,
    }


def ensure_clean_dirs() -> None:
    """确保上传和临时目录存在且为空（启动时调用）。"""
    for d in (DEFAULT_UPLOAD_DIR, DEFAULT_TEMP_DIR):
        d.mkdir(parents=True, exist_ok=True)

    # 清理启动前的残留文件
    result = cleanup_stale_files(max_age_hours=0)  # max_age=0 清理全部
    if result["deleted_count"]:
        logger.info("启动时清理了 %d 个残留文件", result["deleted_count"])
