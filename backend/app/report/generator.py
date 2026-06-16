"""PDF 安全分析报告生成器 — 支持 reportlab 直接生成和 Markdown→HTML→PDF 两种模式"""

import ast
import io
import json
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

from .renderer import render_markdown

logger = logging.getLogger(__name__)

PAGE_W, PAGE_H = A4


def _build_styles():
    """构建报告专用样式。"""
    base = getSampleStyleSheet()
    styles = {
        "title": ParagraphStyle(
            "ReportTitle", parent=base["Title"], fontSize=22, spaceAfter=6 * mm, textColor=colors.HexColor("#1a1a2e")
        ),
        "h2": ParagraphStyle(
            "ReportH2", parent=base["Heading2"], fontSize=14, spaceBefore=8 * mm, spaceAfter=4 * mm, textColor=colors.HexColor("#16213e")
        ),
        "h3": ParagraphStyle(
            "ReportH3", parent=base["Heading3"], fontSize=12, spaceBefore=5 * mm, spaceAfter=2 * mm, textColor=colors.HexColor("#0f3460")
        ),
        "body": ParagraphStyle(
            "ReportBody", parent=base["Normal"], fontSize=10, leading=16, spaceAfter=2 * mm
        ),
        "code": ParagraphStyle(
            "ReportCode", parent=base["Code"], fontSize=8, leading=12, backColor=colors.HexColor("#f4f4f4"), borderPadding=4
        ),
        "footer": ParagraphStyle(
            "ReportFooter", parent=base["Normal"], fontSize=8, textColor=colors.gray
        ),
        "severity_high": ParagraphStyle("SevHigh", parent=base["Normal"], fontSize=10, textColor=colors.red),
        "severity_medium": ParagraphStyle("SevMed", parent=base["Normal"], fontSize=10, textColor=colors.orange),
        "severity_low": ParagraphStyle("SevLow", parent=base["Normal"], fontSize=10, textColor=colors.green),
    }
    return styles


def _parse_result(result_json: str) -> dict:
    """安全解析 result_json 字符串为 dict，兼容引擎返回的嵌套结构。"""
    try:
        raw = json.loads(result_json) if result_json else {}
    except (json.JSONDecodeError, TypeError):
        try:
            return ast.literal_eval(result_json) if result_json else {}
        except (ValueError, SyntaxError):
            return {"raw": result_json}

    if not isinstance(raw, dict):
        return {"raw": result_json}

    # 尝试从 result 字段中提取 LLM 输出的 JSON 报告
    extracted_report = None
    result_text = raw.get("result", "")
    if result_text and isinstance(result_text, str):
        import re
        json_block_match = re.search(r'```json\s*([\s\S]*?)```', result_text)
        if json_block_match:
            try:
                extracted_report = json.loads(json_block_match.group(1).strip())
            except (json.JSONDecodeError, TypeError):
                pass
        if not extracted_report:
            try:
                extracted_report = json.loads(result_text)
            except (json.JSONDecodeError, TypeError):
                pass
    elif result_text and isinstance(result_text, dict):
        extracted_report = result_text

    # 合并提取的报告和原始数据
    merged = {**raw}
    if extracted_report and isinstance(extracted_report, dict):
        for key, value in extracted_report.items():
            if value is not None and value != "":
                merged[key] = value

    # 如果没有 findings/vulnerabilities 但有 aggregated.key_findings，从聚合数据构建
    if not merged.get("findings") and not merged.get("vulnerabilities") and raw.get("aggregated", {}).get("key_findings"):
        findings = raw["aggregated"]["key_findings"]
        if isinstance(findings, list) and findings:
            vuln_findings = [f for f in findings if isinstance(f, dict) and f.get("source") in ("scan_code", "query_cwe", "query_cve")]
            if vuln_findings:
                merged["findings"] = vuln_findings
        elif isinstance(findings, dict):
            if findings.get("iocs"):
                merged["iocs"] = findings["iocs"]
            if findings.get("attack_techniques"):
                merged["attack_mapping"] = findings["attack_techniques"]
            if findings.get("yara_matches"):
                merged["yara_matches"] = findings["yara_matches"]

    # 如果没有 summary，从 aggregated.summary 构建
    if not merged.get("summary") and raw.get("aggregated", {}).get("summary"):
        merged["summary"] = raw["aggregated"]["summary"]

    return merged


def _build_info_section(task, styles):
    """基本信息区域。"""
    elements = [Paragraph("安全分析报告", styles["title"])]
    elements.append(Paragraph("基本信息", styles["h2"]))

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
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
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
        md_text, extensions=["tables", "fenced_code", "codehilite", "toc"]
    )

    # 包装完整 HTML，配置中文字体
    html_full = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<style>
  @page {{ size: A4; margin: 2cm; }}
  body {{ font-family: "DejaVu Sans", "Arial", sans-serif; font-size: 11pt; line-height: 1.6; color: #222; }}
  h1 {{ font-size: 22pt; color: #1a1a2e; border-bottom: 2px solid #1a1a2e; padding-bottom: 8px; }}
  h2 {{ font-size: 15pt; color: #16213e; margin-top: 24px; border-bottom: 1px solid #ccc; padding-bottom: 4px; }}
  h3 {{ font-size: 12pt; color: #0f3460; margin-top: 18px; }}
  table {{ border-collapse: collapse; width: 100%; margin: 12px 0; }}
  th, td {{ border: 1px solid #ccc; padding: 6px 10px; text-align: left; }}
  th {{ background-color: #e8e8e8; font-weight: bold; }}
  code {{ background-color: #f4f4f4; padding: 1px 4px; border-radius: 3px; font-size: 9pt; }}
  pre {{ background-color: #f4f4f4; padding: 12px; border-radius: 4px; font-size: 9pt; overflow-x: auto; }}
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

    if pisa_status.err:
        logger.warning("xhtml2pdf 转换有警告，回退到 reportlab 模式")
        return _generate_pdf_reportlab(task)

    buf.seek(0)
    return buf.read()


def _generate_pdf_reportlab(task) -> bytes:
    """reportlab 直接生成 PDF（兜底方案）。"""
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
