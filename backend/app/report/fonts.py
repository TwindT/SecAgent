"""中文字体注册工具 — 为 reportlab / xhtml2pdf 提供中文渲染支持。

自动搜索系统中可用的中文字体并注册到 reportlab 字体引擎，
确保 PDF 报告中的中文内容能正确显示。

支持平台：
- Windows: Microsoft YaHei / SimHei / SimSun
- Linux:   Noto Sans CJK / WenQuanYi Zen Hei / Source Han Sans
- macOS:   PingFang SC / STHeiti / Hiragino Sans GB
"""

import logging
import platform
from pathlib import Path

from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

logger = logging.getLogger(__name__)

# 注册后的字体名称（在 reportlab 和 CSS 中统一使用）
FONT_NAME = "SecAgentCJK"
FONT_NAME_BOLD = "SecAgentCJK-Bold"

# 各平台候选字体路径（按优先级排列）
_CANDIDATES: dict[str, list[tuple[str, str, str | None]]] = {
    # (字体名, 字体文件路径, 粗体文件路径或None)
    "Windows": [
        ("Microsoft YaHei", "C:/Windows/Fonts/msyh.ttc", "C:/Windows/Fonts/msyhbd.ttc"),
        ("SimHei", "C:/Windows/Fonts/simhei.ttf", None),
        ("SimSun", "C:/Windows/Fonts/simsun.ttc", None),
    ],
    "Linux": [
        ("Noto Sans CJK SC", "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
         "/usr/share/fonts/opentype/noto/NotoSansCJK-Bold.ttc"),
        ("Noto Sans CJK SC", "/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc",
         "/usr/share/fonts/truetype/noto/NotoSansCJK-Bold.ttc"),
        ("WenQuanYi Zen Hei", "/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc", None),
        ("WenQuanYi Micro Hei", "/usr/share/fonts/truetype/wqy/wqy-microhei.ttc", None),
        ("Source Han Sans SC", "/usr/share/fonts/opentype/source-han-sans/SourceHanSansSC-Regular.otf",
         "/usr/share/fonts/opentype/source-han-sans/SourceHanSansSC-Bold.otf"),
    ],
    "Darwin": [
        ("PingFang SC", "/System/Library/Fonts/PingFang.ttc", None),
        ("STHeiti", "/System/Library/Fonts/STHeiti Light.ttc", None),
        ("Hiragino Sans GB", "/System/Library/Fonts/Hiragino Sans GB.ttc", None),
    ],
}

_registered = False


def _find_font() -> tuple[str | None, str | None]:
    """搜索系统中可用的中文字体，返回 (常规字体路径, 粗体字体路径)。"""
    system = platform.system()
    candidates = _CANDIDATES.get(system, [])

    for name, regular_path, bold_path in candidates:
        if Path(regular_path).exists():
            logger.info("找到中文字体: %s (%s)", name, regular_path)
            return regular_path, bold_path if bold_path and Path(bold_path).exists() else None

    logger.warning("未找到系统中文字体，PDF 中文可能无法正常显示。"
                   "请安装字体: apt install fonts-noto-cjk (Linux) 或确认 Windows 字体目录")
    return None, None


def register_cjk_font() -> bool:
    """注册中文字体到 reportlab 字体引擎。

    Returns:
        bool: 是否成功注册中文字体
    """
    global _registered
    if _registered:
        return True

    regular_path, bold_path = _find_font()

    if not regular_path:
        _registered = False
        return False

    try:
        # .ttc 文件需要指定 subfontIndex
        subfont = 0 if regular_path.endswith(".ttc") else None
        kwargs = {"subfontIndex": subfont} if subfont is not None else {}

        pdfmetrics.registerFont(TTFont(FONT_NAME, regular_path, **kwargs))

        if bold_path:
            subfont_bold = 0 if bold_path.endswith(".ttc") else None
            kwargs_bold = {"subfontIndex": subfont_bold} if subfont_bold is not None else {}
            pdfmetrics.registerFont(TTFont(FONT_NAME_BOLD, bold_path, **kwargs_bold))
        else:
            # 没有粗体字体时，用常规字体代替
            pdfmetrics.registerFont(TTFont(FONT_NAME_BOLD, regular_path, **kwargs))

        # 注册字体族，使 <b> 标签能自动使用粗体
        from reportlab.pdfbase.pdfmetrics import registerFontFamily
        registerFontFamily(
            FONT_NAME,
            normal=FONT_NAME,
            bold=FONT_NAME_BOLD,
            italic=FONT_NAME,
            boldItalic=FONT_NAME_BOLD,
        )

        _registered = True
        logger.info("中文字体注册成功: %s", FONT_NAME)
        return True

    except Exception as e:
        logger.error("中文字体注册失败: %s", e)
        _registered = False
        return False


def get_font_css_family() -> str:
    """获取 CSS 中使用的字体族声明。"""
    if _registered:
        return f'"{FONT_NAME}", "Noto Sans CJK SC", "Microsoft YaHei", "SimHei", sans-serif'
    # 降级方案：使用系统可能有的中文字体
    return '"Noto Sans CJK SC", "Microsoft YaHei", "SimHei", "WenQuanYi Zen Hei", sans-serif'
