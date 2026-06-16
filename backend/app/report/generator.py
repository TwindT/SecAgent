"""PDF 安全分析报告生成器 — 支持 reportlab 直接生成和 Markdown→HTML→PDF 两种模式"""

import io
import logging
from datetime import datetime, timezone

import markdown
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from xhtml2pdf import pisa

from .fonts import FONT_NAME, FONT_NAME_BOLD, register_cjk_font, get_font_css_family
from .renderer import render_markdown, _parse_result

logger = logging.getLogger(__name__)

PAGE_W, PAGE_H = A4

# 模块加载时注册中文字体
_cjk_available = register_cjk_font()


def _build_styles():
    """构建报告专用样式（使用中文字体）。"""
    base = getSampleStyleSheet()
    font = FONT_NAME if _cjk_available else "Helvetica"
    font_bold = FONT_NAME_BOLD if _cjk_available else "Helvetica-Bold"

    styles = {
        "title": ParagraphStyle(
            "ReportTitle", parent=base["Title"], fontName=font_bold,
            fontSize=22, spaceAfter=6 * mm, textColor=colors.HexColor("#1a1a2e")
        ),
        "h2": ParagraphStyle(
            "ReportH2", parent=base["Heading2"], fontName=font_bold,
            fontSize=14, spaceBefore=8 * mm, spaceAfter=4 * mm, textColor=colors.HexColor("#16213e")
        ),
        "h3": ParagraphStyle(
            "ReportH3", parent=base["Heading3"], fontName=font_bold,
            fontSize=12, spaceBefore=5 * mm, spaceAfter=2 * mm, textColor=colors.HexColor("#0f3460")
        ),
        "body": ParagraphStyle(
            "ReportBody", parent=base["Normal"], fontName=font,
            fontSize=10, leading=16, spaceAfter=2 * mm
        ),
        "code": ParagraphStyle(
            "ReportCode", parent=base["Code"], fontName="Courier",
            fontSize=8, leading=12, backColor=colors.HexColor("#f4f4f4"), borderPadding=4
        ),
        "footer": ParagraphStyle(
            "ReportFooter", parent=base["Normal"], fontName=font,
            fontSize=8, textColor=colors.gray
        ),
        "severity_high": ParagraphStyle("SevHigh", parent=base["Normal"], fontName=font, fontSize=10, textColor=colors.red),
        "severity_medium": ParagraphStyle("SevMed", parent=base["Normal"], fontName=font, fontSize=10, textColor=colors.orange),
        "severity_low": ParagraphStyle("SevLow", parent=base["Normal"], fontName=font, fontSize=10, textColor=colors.green),
    }
    return styles


def _build_info_section(task, styles):
    """基本信息区域。"""
    elements = [Paragraph("安全分析报告", styles["title"])]
    elements.append(Paragraph("基本信息", styles["h2"]))

    font_bold = FONT_NAME_BOLD if _cjk_available else "Helvetica-Bold"
    font_normal = FONT_NAME if _cjk_available else "Helvetica"

    info_data = [
        ["任务 ID", str(task.id)],
        ["任务类型", "代码漏洞检测" if "vuln" in (getattr(task.type, "value", str(task.type)) or "") else "恶意代码分析"],
        ["分析状态", task.status or "-"],
        ["创建时间", task.created_at.strftime("%Y-%m-%d %H:%M:%S") if task.created_at else "-"],
        ["更新时间", task.updated_at.strftime("%Y-%m-%d %H:%M:%S") if task.updated_at else "-"],
    ]

    table = Table(info_data, colWidths=[40 * mm, 120 * mm])
    table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e8e8e8")),
        ("PADDING", (0, 0), (-1, -1), 6),
        ("FONTNAME", (0, 0), (0, -1), font_bold),
        ("FONTNAME", (1, 0), (1, -1), font_normal),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    elements.append(table)
    return elements


def _build_vuln_section(result: dict, styles):
    """漏洞检测结果区域。"""
    elements = [Paragraph("分析结果", styles["h2"])]

    summary = result.get("summary", {})
    if summary:
        elements.append(Paragraph(f"风险等级: {summary.get('risk_level', '-')}", styles["body"]))
        elements.append(Paragraph(f"置信度: {summary.get('confidence', '-')}", styles["body"]))

    findings = result.get("findings", result.get("vulnerabilities", []))
    if isinstance(findings, list) and findings:
        elements.append(Paragraph(f"共发现 {len(findings)} 个问题", styles["h3"]))
        for i, vuln in enumerate(findings, 1):
            if isinstance(vuln, dict):
                title = vuln.get("title", vuln.get("name", f"问题 {i}"))
                severity = vuln.get("severity", "-")
                desc = vuln.get("description", vuln.get("detail", ""))
                cwe = vuln.get("cwe_id", vuln.get("cwe", ""))
                sev_color = {"high": "red", "medium": "orange", "low": "green"}.get(str(severity).lower(), "black")

                elements.append(Paragraph(
                    f"<b>{i}. {title}</b> "
                    f'<font color="{sev_color}">[{str(severity).upper()}]</font>'
                    f"{'  CWE-' + str(cwe) if cwe else ''}",
                    styles["body"]
                ))
                if desc:
                    elements.append(Paragraph(str(desc)[:300], styles["body"]))
                elements.append(Spacer(1, 3 * mm))
    else:
        elements.append(Paragraph("暂无详细分析结果", styles["body"]))

    return elements


def _build_malware_section(result: dict, styles):
    """恶意代码分析结果区域。"""
    elements = [Paragraph("分析结果", styles["h2"])]

    verdict = result.get("verdict", result.get("malicious", ""))
    confidence = result.get("confidence", "")
    elements.append(Paragraph(f"判定: {verdict} (置信度: {confidence})", styles["body"]))

    behaviors = result.get("behaviors", result.get("behavior", []))
    if isinstance(behaviors, list) and behaviors:
        elements.append(Paragraph("检测到的行为:", styles["h3"]))
        for b in behaviors:
            elements.append(Paragraph(f"• {str(b)}", styles["body"]))

    iocs = result.get("iocs", result.get("ioc", []))
    if isinstance(iocs, list) and iocs:
        elements.append(Paragraph("IOC 清单:", styles["h3"]))
        for ioc in iocs:
            if isinstance(ioc, dict):
                elements.append(Paragraph(
                    f"• [{ioc.get('type', '-')}] {ioc.get('value', '-')}", styles["body"]))

    return elements


def generate_pdf(task) -> bytes:
    """根据任务生成 PDF 报告（Markdown→HTML→PDF 主流程）。

    参数:
        task: SQLAlchemy Task ORM 对象

    返回:
        bytes: PDF 文件二进制数据
    """
    return generate_pdf_from_markdown(task)


def generate_pdf_from_markdown(task) -> bytes:
    """Markdown → HTML → PDF 转换链路。

    1. 从分析结果 JSON 渲染 Markdown 报告
    2. Markdown 转 HTML（含中文字体支持）
    3. HTML 转 PDF（通过 xhtml2pdf/pisa）
    """
    md_text = render_markdown(task)

    # Markdown → HTML
    html_body = markdown.markdown(
        md_text, extensions=["tables", "fenced_code", "toc"]
    )

    # 获取 CSS 字体族声明
    font_css = get_font_css_family()

    # 包装完整 HTML，配置中文字体
    html_full = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<style>
  @page {{ size: A4; margin: 2cm; }}
  body {{ font-family: {font_css}; font-size: 11pt; line-height: 1.6; color: #222; }}
  h1 {{ font-size: 22pt; color: #1a1a2e; border-bottom: 2px solid #1a1a2e; padding-bottom: 8px; }}
  h2 {{ font-size: 15pt; color: #16213e; margin-top: 24px; border-bottom: 1px solid #ccc; padding-bottom: 4px; }}
  h3 {{ font-size: 12pt; color: #0f3460; margin-top: 18px; }}
  table {{ border-collapse: collapse; width: 100%; margin: 12px 0; }}
  th, td {{ border: 1px solid #ccc; padding: 6px 10px; text-align: left; }}
  th {{ background-color: #e8e8e8; font-weight: bold; }}
  code {{ background-color: #f4f4f4; padding: 1px 4px; font-size: 9pt; }}
  pre {{ background-color: #f4f4f4; padding: 12px; font-size: 9pt; }}
  blockquote {{ border-left: 3px solid #ccc; margin-left: 0; padding-left: 16px; color: #555; }}
  hr {{ border: none; border-top: 1px solid #ddd; margin: 20px 0; }}
  .footer {{ text-align: center; color: #888; font-size: 8pt; margin-top: 30px; }}
</style>
</head>
<body>
{html_body}
</body>
</html>"""

    # HTML → PDF
    buf = io.BytesIO()
    pisa_status = pisa.CreatePDF(src=html_full, dest=buf, encoding="utf-8")

    # 判断是否真正生成失败：仅当 PDF 内容为空时才回退
    # xhtml2pdf 经常对不支持的 CSS 产生非零 err，但 PDF 实际生成成功
    buf.seek(0)
    pdf_content = buf.read()

    if len(pdf_content) < 100:
        logger.warning("xhtml2pdf 生成的 PDF 过小 (%d 字节)，可能失败，回退到 reportlab 模式", len(pdf_content))
        return _generate_pdf_reportlab(task)

    if pisa_status.err:
        logger.info("xhtml2pdf 有 %d 个警告，但 PDF 已成功生成 (%d 字节)，忽略警告", pisa_status.err, len(pdf_content))

    return pdf_content


def _generate_pdf_reportlab(task) -> bytes:
    """reportlab 直接生成 PDF（兜底方案，使用中文字体）。"""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=20 * mm, bottomMargin=20 * mm)
    styles = _build_styles()

    elements = _build_info_section(task, styles)

    if task.result_json:
        result = _parse_result(task.result_json)
        if "vuln" in (getattr(task.type, "value", str(task.type)) or ""):
            elements.extend(_build_vuln_section(result, styles))
        else:
            elements.extend(_build_malware_section(result, styles))
    else:
        elements.append(Paragraph("分析尚未完成，暂无结果。", styles["body"]))

    elements.append(Spacer(1, 15 * mm))
    elements.append(Paragraph(
        f"报告生成时间: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}  |  SecAgent",
        styles["footer"]
    ))

    doc.build(elements)
    buf.seek(0)
    return buf.read()
