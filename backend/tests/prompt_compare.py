"""
3.2 Prompt 调优 — 对比测试脚本

运行方式:
  python prompt_compare.py           # 测试当前 prompt
  python prompt_compare.py --after   # 测试调优后 prompt (需要先调优)
"""
import os
import re
import sys
import json
import time
import subprocess

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.samples_3_2 import SAMPLES_3_2

_ANSI_RE = re.compile(r"\033\[[0-9;]*m")


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)

DEMO_SCRIPT = os.path.join(os.path.dirname(__file__), "..", "app", "agent", "demo_cli2.py")


def run_sample(sample: dict, after: bool = False) -> dict:
    """运行单个样本，返回评估结果。"""
    tmp_file = os.path.join(os.path.dirname(__file__), "samples", f"_prompt_test_{sample['id']}.txt")
    with open(tmp_file, "w", encoding="utf-8") as f:
        f.write(sample["code"])

    cmd = [
        sys.executable, DEMO_SCRIPT,
        "--file", tmp_file,
        "--type", sample["task_type"],
        "--max-steps", "8",
        "--quiet",
        "--mock-only",
    ]
    if after:
        cmd.append("--after")  # 暂未实现，预留

    proc = subprocess.run(
        cmd,
        capture_output=True, text=True,
        encoding="utf-8", errors="replace",
        timeout=180,
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
    )
    try:
        os.remove(tmp_file)
    except OSError:
        pass

    stdout = _strip_ansi(proc.stdout)
    result = {
        "sample_id": sample["id"],
        "sample_name": sample["name"],
        "success": "ERROR:" not in stdout,
        "output_length": len(stdout),
        "issues_found": [],
        "issues_missed": [],
        "false_positives": [],
        "tool_calls": [],
        "tool_count": 0,
        "confidence": "unknown",
        "confidence_score": 0,
        "notes": [],
    }

    # 检查命中
    lower = stdout.lower()
    for issue in sample["expected_issues"]:
        if issue.lower() in lower:
            result["issues_found"].append(issue)
        else:
            result["issues_missed"].append(issue)

    # 检查不应报告的内容 (误报)
    for fp in sample.get("should_not_report", []):
        if fp.lower() in lower:
            result["false_positives"].append(fp)

    # 提取置信度
    for line in stdout.split("\n"):
        if "综合置信度:" in line:
            for level in ["HIGH", "MEDIUM", "LOW"]:
                if level in line.upper():
                    result["confidence"] = level.lower()
            try:
                if "(" in line and "/100)" in line:
                    result["confidence_score"] = int(line.split("(")[1].split("/100")[0])
            except (ValueError, IndexError):
                pass

    # 提取工具调用次数
    for line in stdout.split("\n"):
        if "工具调用:" in line and "次" in line:
            try:
                result["tool_count"] = int(line.split("工具调用:")[1].split("次")[0].strip())
            except (ValueError, IndexError):
                pass

    # 记录问题行为
    if "ERROR:" in stdout:
        idx = stdout.index("ERROR:")
        end = stdout.index("\n", idx) if "\n" in stdout[idx:] else len(stdout)
        result["notes"].append(f"ERROR: {stdout[idx:end].strip()}")

    # 检查是否未调用工具直接下结论
    if result["tool_count"] == 0 and result["success"]:
        result["notes"].append("潜在问题: 未调用任何工具")

    # 检查是否提到具体代码行号/证据
    has_evidence = any(kw in lower for kw in ["line", "行", "代码片段", "code_snippet", "第"])
    if not has_evidence and sample["task_type"] == "vulnerability_detection":
        result["notes"].append("潜在问题: 缺少代码行号/证据引用")

    return result


def print_comparison(before: list[dict], after: list[dict] = None) -> None:
    """打印测试结果对比。"""
    print("\n" + "=" * 85)
    print("  3.2 Prompt 调优 — 测试结果")
    print("=" * 85)

    results = before
    label = "当前 Prompt"
    if after:
        results = after
        label = "调优后 Prompt"

    for r in results:
        print(f"\n  [{r['sample_id']}] {r['sample_name']}  ({label})")
        print(f"    状态: {'PASS' if r['success'] else 'FAIL'} | "
              f"置信度: {r['confidence']}({r['confidence_score']}) | "
              f"工具调用: {r['tool_count']}次")
        print(f"    命中: {r['issues_found']}" if r['issues_found'] else "    命中: (无)")
        if r['issues_missed']:
            print(f"    漏检: {r['issues_missed']}")
        if r['false_positives']:
            print(f"    误报: {r['false_positives']}")
        if r['notes']:
            for n in r['notes']:
                print(f"    \033[93m{n}\033[0m")

    # 汇总
    total_hit = sum(len(r["issues_found"]) for r in results)
    total_miss = sum(len(r["issues_missed"]) for r in results)
    total_fp = sum(len(r["false_positives"]) for r in results)
    hit_rate = total_hit * 100 // max(1, total_hit + total_miss)

    print(f"\n  --- {label} 汇总 ---")
    print(f"  发现命中率: {total_hit}/{total_hit + total_miss} ({hit_rate}%)")
    print(f"  误报数: {total_fp}")
    print(f"  成功率: {sum(1 for r in results if r['success'])}/{len(results)}")
    print(f"  平均置信度: {sum(r['confidence_score'] for r in results if r['confidence_score']) // max(1, sum(1 for r in results if r['confidence_score']))}")

    if before and after:
        print(f"\n  --- 改进对比 ---")
        before_hit = sum(len(r["issues_found"]) for r in before)
        after_hit = sum(len(r["issues_found"]) for r in after)
        before_miss = sum(len(r["issues_missed"]) for r in before)
        after_miss = sum(len(r["issues_missed"]) for r in after)
        print(f"  命中: {before_hit} → {after_hit} ({after_hit - before_hit:+d})")
        print(f"  漏检: {before_miss} → {after_miss} ({after_miss - before_miss:+d})")


def main():
    after_mode = "--after" in sys.argv
    print(f"\n模式: {'调优后 Prompt 测试' if after_mode else '当前 Prompt 基线测试'}")
    print(f"样本数: {len(SAMPLES_3_2)}")

    results = []
    for sample in SAMPLES_3_2:
        print(f"  [{sample['id']}/3] 测试: {sample['name']}...", end=" ", flush=True)
        r = run_sample(sample, after=after_mode)
        results.append(r)
        hit = len(r["issues_found"])
        miss = len(r["issues_missed"])
        print(f"命中 {hit}/{hit+miss} | 置信度 {r['confidence']}({r['confidence_score']}) | 工具调用 {r['tool_count']}次")

    print_comparison(results)

    label = "after" if after_mode else "before"
    report_path = os.path.join(os.path.dirname(__file__), f"prompt_eval_{label}.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print(f"\n评估报告: {report_path}")


if __name__ == "__main__":
    main()
