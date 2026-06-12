"""
3.3 文件特征提取工具 — PE 分析 / 字符串提取 / Office 宏分析 / 文件类型识别。

提供 extract_file_features 工具入口函数，
统一由 AgentEngine 通过 register_tool() 调用。
"""

import os
import re
import struct
import hashlib
import logging
from datetime import datetime
from typing import Optional

import pefile

logger = logging.getLogger(__name__)


# ======================================================================
# 3.3.2 PE 文件分析
# ======================================================================

def _analyze_pe(file_path: str) -> dict:
    """解析 PE (Portable Executable) 文件，提取导入表、节区信息、编译时间戳等。

    Returns
    -------
    dict
        {
            "is_pe": True/False,
            "machine": str,
            "entry_point": str,
            "timestamp": str (ISO),
            "subsystem": str,
            "imports": [{"dll": str, "functions": [str]}],
            "sections": [{"name": str, "virtual_address": str, "virtual_size": int,
                          "raw_size": int, "entropy": float, "characteristics": str}],
            "has_debug": bool,
            "is_signed": bool,
        }
    """
    result = {
        "is_pe": False,
        "machine": "",
        "entry_point": "",
        "timestamp": "",
        "subsystem": "",
        "imports": [],
        "sections": [],
        "has_debug": False,
        "is_signed": False,
    }

    try:
        pe = pefile.PE(file_path, fast_load=True)
        result["is_pe"] = True

        # -- 基本信息 --
        # Machine type
        machine_types = {
            0x014C: "I386 (32-bit)",
            0x8664: "AMD64 (64-bit)",
            0x0200: "IA64",
            0x01C4: "ARM",
            0xAA64: "ARM64",
        }
        machine = pe.FILE_HEADER.Machine
        result["machine"] = machine_types.get(machine, f"0x{machine:04X}")

        # Entry point
        result["entry_point"] = f"0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:08X}"

        # Compile timestamp
        ts = pe.FILE_HEADER.TimeDateStamp
        result["timestamp"] = datetime.utcfromtimestamp(ts).isoformat() + "Z"

        # Subsystem
        subsystem_map = {
            2: "GUI",
            3: "Console",
            1: "Native",
        }
        subsystem = pe.OPTIONAL_HEADER.Subsystem
        result["subsystem"] = subsystem_map.get(subsystem, f"Unknown({subsystem})")

        # Debug info
        result["has_debug"] = hasattr(pe, "DIRECTORY_ENTRY_DEBUG")

        # Digital signature (简单检测)
        security = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]  # IMAGE_DIRECTORY_ENTRY_SECURITY
        result["is_signed"] = security.VirtualAddress != 0 or security.Size != 0

        # -- 导入表 --
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("utf-8", errors="replace")
                functions = []
                for imp in entry.imports:
                    if imp.name:
                        functions.append(imp.name.decode("utf-8", errors="replace"))
                    elif imp.ordinal:
                        functions.append(f"ordinal:{imp.ordinal}")
                result["imports"].append({
                    "dll": dll_name,
                    "functions": functions[:50],  # 最多取 50 个，避免过大
                })
                if len(result["imports"]) >= 30:
                    break  # 最多取 30 个 DLL

        # -- 节区信息 --
        for section in pe.sections:
            name = section.Name.decode("utf-8", errors="replace").rstrip("\x00")
            entropy = _calculate_entropy(section.get_data())
            characteristics = _section_characteristics(section.Characteristics)
            result["sections"].append({
                "name": name,
                "virtual_address": f"0x{section.VirtualAddress:08X}",
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "entropy": round(entropy, 2),
                "characteristics": characteristics,
            })

        pe.close()
        return result

    except pefile.PEFormatError as e:
        logger.info("文件不是有效 PE 格式: %s", e)
        result["is_pe"] = False
        return result
    except Exception as e:
        logger.exception("PE 分析异常: %s", e)
        result["is_pe"] = False
        return result


def _calculate_entropy(data: bytes) -> float:
    """计算字节数据的 Shannon 熵值（0-8）。越高表示数据越随机/加密。"""
    import math
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    entropy = 0.0
    for c in counts:
        if c > 0:
            p = c / total
            entropy -= p * math.log2(p)
    return entropy


def _section_characteristics(flags: int) -> str:
    """将节区特征标志位转换为可读字符串。"""
    char_map = {
        0x00000020: "CODE",
        0x00000040: "INIT_DATA",
        0x00000080: "UNINIT_DATA",
        0x02000000: "DISCARDABLE",
        0x04000000: "NOT_CACHED",
        0x08000000: "NOT_PAGED",
        0x10000000: "SHARED",
        0x20000000: "EXECUTE",
        0x40000000: "READ",
        0x80000000: "WRITE",
    }
    attrs = []
    for bit, name in sorted(char_map.items(), reverse=True):
        if flags & bit:
            attrs.append(name)
    return "|".join(attrs) if attrs else "NONE"


# ======================================================================
# 3.3.3 文件字符串提取
# ======================================================================

def _extract_strings(file_path: str, min_length: int = 4) -> list[str]:
    """从文件中提取所有可打印字符串（默认最小长度 4）。

    支持 UTF-8 / UTF-16 LE / ASCII 编码的字符串提取。
    """
    try:
        with open(file_path, "rb") as f:
            data = f.read()
    except Exception as e:
        logger.error("读取文件失败: %s", e)
        return []

    strings: list[str] = []
    ascii_pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_length)

    # ASCII
    for match in ascii_pattern.finditer(data):
        s = match.group().decode("ascii", errors="replace")
        strings.append(s)

    # UTF-16 LE (wide strings)
    wide_pattern = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_length)
    for match in wide_pattern.finditer(data):
        try:
            s = match.group().decode("utf-16-le", errors="replace")
            strings.append(s)
        except Exception:
            pass

    # 去重并保留顺序
    seen: set[str] = set()
    uniq: list[str] = []
    for s in strings:
        if s not in seen:
            seen.add(s)
            uniq.append(s)

    return uniq


def _classify_strings(strings: list[str]) -> dict:
    """将提取的字符串按类型分类。"""
    result = {
        "ipv4": [],
        "urls": [],
        "file_paths": [],
        "registry_keys": [],
        "suspicious": [],
        "total": len(strings),
    }

    ipv4_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    url_re = re.compile(r"https?://[^\s]{4,}")
    path_re = re.compile(r"(?:[A-Za-z]:\\|/)[^\s]{4,}(?:\.(?:exe|dll|sys|bat|ps1|vbs|js|tmp|dat|txt|ini|conf|xml|json))", re.I)
    reg_re = re.compile(r"(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_)[^\s]{4,}", re.I)
    susp_keywords = [
        "cmd.exe", "powershell", "wscript", "cscript", "rundll32",
        "CreateProcess", "ShellExecute", "WinExec", "VirtualAlloc",
        "WriteProcessMemory", "LoadLibrary", "GetProcAddress",
        "socket", "connect", "recv", "send", "bind",
        "Mozilla/", "Content-Type", "User-Agent",
        "base64", "XOR", "RC4", "AES",
    ]

    for s in strings:
        if ipv4_re.search(s):
            result["ipv4"].append(s[:200])
        if url_re.search(s):
            result["urls"].append(s[:500])
        if path_re.search(s):
            result["file_paths"].append(s[:200])
        if reg_re.search(s):
            result["registry_keys"].append(s[:200])
        for kw in susp_keywords:
            if kw.lower() in s.lower():
                result["suspicious"].append(s[:300])
                break

    # 限制每类最多 200 条
    for key in ("ipv4", "urls", "file_paths", "registry_keys", "suspicious"):
        result[key] = result[key][:200]

    return result


# ======================================================================
# 3.3.4 Office 文档分析
# ======================================================================

def _analyze_office(file_path: str) -> dict:
    """分析 Office 文档（OLE 格式如 .doc/.xls + OpenXML 格式如 .docx/.xlsx）。

    Returns
    -------
    dict
        {
            "is_office": True/False,
            "format": "OLE"|"OpenXML"|"",
            "has_macros": bool,
            "vba_code": str | None,
            "ole_streams": [str],
        }
    """
    result = {
        "is_office": False,
        "format": "",
        "has_macros": False,
        "vba_code": None,
        "ole_streams": [],
    }

    ext = os.path.splitext(file_path)[1].lower()

    # OpenXML (.docx, .xlsx, .pptx 等)
    if ext in (".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm"):
        result["is_office"] = True
        result["format"] = "OpenXML"
        vba = _extract_openxml_vba(file_path)
        if vba:
            result["has_macros"] = True
            result["vba_code"] = vba
        return result

    # OLE 格式 (.doc, .xls, .ppt 等)
    if ext in (".doc", ".xls", ".ppt", ".dot", ".xla", ".ppa"):
        result["is_office"] = True
        result["format"] = "OLE"
        ole_info = _analyze_ole(file_path)
        result["has_macros"] = ole_info["has_macros"]
        result["vba_code"] = ole_info.get("vba_code")
        result["ole_streams"] = ole_info.get("streams", [])
        return result

    return result


def _analyze_ole(file_path: str) -> dict:
    """分析 OLE 格式文件（如 .doc, .xls），检测 VBA 宏。"""
    info = {"has_macros": False, "vba_code": None, "streams": []}

    try:
        import olefile
        if not olefile.isOleFile(file_path):
            return info

        ole = olefile.OleFileIO(file_path)
        stream_list = ole.listdir()
        info["streams"] = ["/".join(s) for s in stream_list]

        # 检测 VBA 宏存储流
        macro_streams = [s for s in info["streams"] if "VBA" in s.upper() or "Macro" in s.upper() or "macros" in s.lower()]
        if macro_streams:
            info["has_macros"] = True

        # 尝试提取 _VBA_PROJECT_CUR/VBA/... 中的代码
        for path in stream_list:
            path_str = "/".join(path).lower()
            if "vba" in path_str or "macro" in path_str or "_vba_project" in path_str:
                try:
                    raw = ole.openstream(path).read()
                    # 尝试提取纯文本部分（VBA 代码嵌入在 OLE 流中，有大量二进制数据）
                    text = _extract_printable_from_bytes(raw)
                    if text and len(text) > 20:
                        if info["vba_code"]:
                            info["vba_code"] += "\n\n' --- " + "/".join(path) + " ---\n" + text
                        else:
                            info["vba_code"] = text
                except Exception:
                    pass

        ole.close()
        return info

    except ImportError:
        logger.warning("olefile 未安装，无法分析 OLE 格式文档")
        return info
    except Exception as e:
        logger.error("OLE 分析异常: %s", e)
        return info


def _extract_openxml_vba(file_path: str) -> Optional[str]:
    """从 OpenXML 文件中提取 VBA 宏代码。

    .docm/.xlsm 等文件本质是 ZIP，vbaProject.bin 位于 word/ 或 xl/ 目录下。
    """
    try:
        import zipfile
        vba_code = ""

        with zipfile.ZipFile(file_path, "r") as zf:
            # 检查是否包含 vbaProject.bin
            vba_bin_paths = [
                "word/vbaProject.bin",
                "xl/vbaProject.bin",
                "ppt/vbaProject.bin",
            ]
            vba_bin = None
            for path in vba_bin_paths:
                if path in zf.namelist():
                    vba_bin = path
                    break

            if not vba_bin:
                return None

            # 从 vbaProject.bin 中提取可打印字符串（VBA 源码嵌入在其中）
            raw = zf.read(vba_bin)
            vba_code = _extract_printable_from_bytes(raw)

        return vba_code if vba_code else None

    except ImportError:
        logger.warning("zipfile 不可用")
        return None
    except Exception as e:
        logger.error("OpenXML VBA 提取异常: %s", e)
        return None


def _extract_printable_from_bytes(data: bytes, min_length: int = 10) -> str:
    """从二进制数据中提取可打印文本片段。"""
    result: list[str] = []
    current: list[int] = []
    for b in data:
        if 32 <= b < 127 or b in (9, 10, 13):
            current.append(b)
        else:
            if len(current) >= min_length:
                result.append(bytes(current).decode("ascii", errors="replace"))
            current = []
    if len(current) >= min_length:
        result.append(bytes(current).decode("ascii", errors="replace"))
    return "\n".join(result)


# ======================================================================
# 3.3.5 文件类型自动识别（基于 magic bytes）
# ======================================================================

# 扩展魔数签名库
_MAGIC_SIGNATURES = [
    # (offset, bytes, name, category)
    # PE / DOS
    (0, b"MZ", "PE/DOS executable", "executable"),
    # ELF
    (0, b"\x7fELF", "ELF executable", "executable"),
    # Mach-O
    (0, b"\xfe\xed\xfa\xce", "Mach-O (32-bit)", "executable"),
    (0, b"\xfe\xed\xfa\xcf", "Mach-O (64-bit)", "executable"),
    (0, b"\xce\xfa\xed\xfe", "Mach-O (32-bit, reverse)", "executable"),
    (0, b"\xcf\xfa\xed\xfe", "Mach-O (64-bit, reverse)", "executable"),
    # ZIP-based (Office OpenXML, JAR, APK, etc.)
    (0, b"PK\x03\x04", "ZIP archive / Office OpenXML / JAR", "archive"),
    # Gzip
    (0, b"\x1f\x8b\x08", "GZIP archive", "archive"),
    # RAR
    (0, b"Rar!\x1a\x07", "RAR archive", "archive"),
    (0, b"Rar!\x1a\x07\x00", "RAR5 archive", "archive"),
    # 7-Zip
    (0, b"7z\xbc\xaf\x27\x1c", "7-Zip archive", "archive"),
    # OLE2 (Office 97-2003)
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE2 / Office 97-2003 document", "document"),
    # PDF
    (0, b"%PDF", "PDF document", "document"),
    # RTF
    (0, b"{\\rtf", "RTF document", "document"),
    # PNG
    (0, b"\x89PNG\r\n\x1a\n", "PNG image", "image"),
    # JPEG
    (0, b"\xff\xd8\xff", "JPEG image", "image"),
    # GIF
    (0, b"GIF87a", "GIF image", "image"),
    (0, b"GIF89a", "GIF image", "image"),
    # BMP
    (0, b"BM", "BMP image", "image"),
    # Python script
    (0, b"#!/usr/bin/python", "Python script", "script"),
    (0, b"#!/usr/bin/env python", "Python script", "script"),
    (0, b"#!/bin/python", "Python script", "script"),
    # Shell script
    (0, b"#!/bin/sh", "Shell script", "script"),
    (0, b"#!/bin/bash", "Shell script", "script"),
    # JavaScript
    (0, b"#!/usr/bin/node", "JavaScript", "script"),
    # VBA / macro-enabled
    (0, b"Attribute VB_Name", "VBA macro", "script"),
]


def _detect_file_type(file_path: str) -> dict:
    """通过 magic bytes 检测文件类型，不依赖文件扩展名。

    Returns
    -------
    dict
        {"type": str, "category": str, "confidence": "high"|"medium"|"low"}
    """
    try:
        # 只读前 512 字节足矣
        with open(file_path, "rb") as f:
            header = f.read(512)
    except Exception as e:
        logger.error("读取文件头失败: %s", e)
        return {"type": "unknown", "category": "unknown", "confidence": "low"}

    # 按优先级匹配（长签名优先）
    for offset, magic, name, category in sorted(_MAGIC_SIGNATURES, key=lambda x: -len(x[1])):
        end = offset + len(magic)
        if len(header) >= end and header[offset:end] == magic:
            # 细化分类
            if magic == b"PK\x03\x04":
                name = _refine_zip_type(file_path)
            elif magic == b"MZ":
                # 确认是否为 PE（MZ 也可能是 DOS 程序）
                try:
                    pe_offset = struct.unpack("<I", header[0x3C:0x40])[0]
                    if len(header) > pe_offset and header[pe_offset:pe_offset + 4] == b"PE\x00\x00":
                        name = _refine_pe_type(file_path)
                except Exception:
                    pass
            elif magic == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
                name = _refine_ole_type(file_path)

            return {"type": name, "category": category, "confidence": "high"}

    # 文本文件启发式检测
    try:
        text = header.decode("utf-8", errors="strict")
        if "<html" in text.lower() or "<!doctype html" in text.lower():
            return {"type": "HTML document", "category": "document", "confidence": "high"}
        if "<?xml" in text:
            return {"type": "XML document", "category": "document", "confidence": "high"}
        if "function" in text or "var " in text or "const " in text:
            return {"type": "JavaScript / code", "category": "script", "confidence": "medium"}
        if "import " in text or "def " in text or "class " in text:
            return {"type": "Python script", "category": "script", "confidence": "medium"}
        if "#include" in text:
            return {"type": "C/C++ source", "category": "script", "confidence": "medium"}
        # 纯文本
        printable_ratio = sum(1 for b in header if 32 <= b < 127 or b in (9, 10, 13)) / max(len(header), 1)
        if printable_ratio > 0.9:
            return {"type": "Text file", "category": "text", "confidence": "medium"}
    except UnicodeDecodeError:
        pass

    return {"type": "Binary data / unknown", "category": "unknown", "confidence": "low"}


def _refine_zip_type(file_path: str) -> str:
    """细化 ZIP 类型的识别（Office OpenXML / JAR / APK 等）。"""
    try:
        import zipfile
        with zipfile.ZipFile(file_path, "r") as zf:
            names = [n.lower() for n in zf.namelist()]
            # Office OpenXML
            if any("word/document.xml" in n for n in names):
                return "Microsoft Word (DOCX/DOCM)"
            if any("xl/workbook.xml" in n for n in names):
                return "Microsoft Excel (XLSX/XLSM)"
            if any("ppt/presentation.xml" in n for n in names):
                return "Microsoft PowerPoint (PPTX/PPTM)"
            # JAR
            if any("meta-inf/manifest.mf" in n for n in names):
                return "Java JAR archive"
            # APK
            if "androidmanifest.xml" in names:
                return "Android APK"
            # 通用 ZIP
            return "ZIP archive"
    except Exception:
        return "ZIP archive"


def _refine_pe_type(file_path: str) -> str:
    """细化 PE 类型（DLL / EXE / SYS）。"""
    try:
        pe = pefile.PE(file_path, fast_load=True)
        characteristics = pe.FILE_HEADER.Characteristics
        is_dll = characteristics & 0x2000
        is_sys = characteristics & 0x0800
        pe.close()
        if is_dll:
            return "PE DLL"
        if is_sys:
            return "PE System Driver"
        return "PE executable"
    except Exception:
        return "PE executable"


def _refine_ole_type(file_path: str) -> str:
    """细化 OLE 类型。"""
    ext = os.path.splitext(file_path)[1].lower()
    ole_map = {
        ".doc": "Microsoft Word (DOC)",
        ".dot": "Microsoft Word Template (DOT)",
        ".xls": "Microsoft Excel (XLS)",
        ".xla": "Microsoft Excel Add-in (XLA)",
        ".ppt": "Microsoft PowerPoint (PPT)",
        ".ppa": "Microsoft PowerPoint Add-in (PPA)",
        ".msi": "Microsoft Installer (MSI)",
    }
    return ole_map.get(ext, "OLE2 compound document")


# ======================================================================
# 3.3.6 extract_file_features — 统一入口
# ======================================================================

def extract_file_features(file_path: str) -> dict:
    """提取文件的静态特征信息，作为恶意代码分析的第一步。

    自动识别文件类型，并根据类型执行相应的分析：
    - PE/ELF: 导入表、节区、编译时间戳
    - Office: VBA 宏检测与提取
    - 通用: 字符串提取、Hash 计算

    Parameters
    ----------
    file_path : str
        待分析文件的本地路径。

    Returns
    -------
    dict
        {
            "status": "ok"|"error",
            "data": {
                "file_name": str,
                "file_size": int,
                "md5": str,
                "sha1": str,
                "sha256": str,
                "type_info": {...},
                "pe_info": {...} | None,
                "office_info": {...} | None,
                "strings": {
                    "total": int,
                    "ipv4": [...],
                    "urls": [...],
                    "file_paths": [...],
                    "registry_keys": [...],
                    "suspicious": [...],
                },
            },
            "error": str|None
        }
    """
    # 检查文件是否存在
    if not os.path.exists(file_path):
        return {
            "status": "error",
            "data": None,
            "error": f"文件不存在: {file_path}",
        }

    try:
        # 基本信息
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)

        # 文件 Hash
        with open(file_path, "rb") as f:
            data = f.read()
        md5 = hashlib.md5(data).hexdigest()
        sha1 = hashlib.sha1(data).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()

        # 类型识别
        type_info = _detect_file_type(file_path)
        category = type_info.get("category", "unknown")

        # ---- 按类型分发分析 ----
        pe_info = None
        office_info = None

        if category == "executable" and type_info.get("type", "").startswith("PE"):
            pe_info = _analyze_pe(file_path)

        if category in ("document",) and ("Office" in type_info.get("type", "") or "OLE" in type_info.get("type", "")):
            office_info = _analyze_office(file_path)
        elif category == "archive" and "ZIP" in type_info.get("type", ""):
            # ZIP 可能是 Office OpenXML
            office_info = _analyze_office(file_path)

        # 字符串提取（所有文件通用）
        strings = _extract_strings(file_path, min_length=4)
        classified_strings = _classify_strings(strings)

        # YARA 规则扫描（所有文件通用）
        from .yara_scanner import scan_yara
        yara_scan = scan_yara(file_path)

        return {
            "status": "ok",
            "data": {
                "file_name": file_name,
                "file_size": file_size,
                "md5": md5,
                "sha1": sha1,
                "sha256": sha256,
                "type_info": type_info,
                "pe_info": pe_info,
                "office_info": office_info,
                "yara_scan": yara_scan,
                "strings": classified_strings,
            },
            "error": None,
        }

    except Exception as e:
        logger.exception("extract_file_features 异常: %s", e)
        return {
            "status": "error",
            "data": None,
            "error": str(e),
        }
