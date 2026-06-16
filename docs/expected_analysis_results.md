# 测试样本预期分析结果

> 本文档为所有测试样本的预期分析结果，用于对比验证 Agent 分析的准确性。

---

## 一、漏洞检测样本预期结果

### 1. python_sql_injection.py — SQL 注入

| 项目 | 预期结果 |
|------|----------|
| **漏洞类型** | SQL 注入（CWE-89） |
| **严重等级** | 高危 |
| **检测工具** | semgrep / bandit |
| **漏洞数量** | 4 处 |
| **漏洞位置** | `get_user_by_username()` f-string 拼接、`search_users()` %格式化、`delete_user()` 字符串拼接、`login()` f-string 拼接 |
| **关键规则** | bandit: B608 (hardcoded_sql_expressions), semgrep: python.lang.security.audit.dangerous-system-call |
| **修复建议** | 使用参数化查询（? 占位符），使用 ORM 框架，对输入进行验证和转义 |
| **置信度** | ≥ 90% |

### 2. python_command_injection.py — 命令注入

| 项目 | 预期结果 |
|------|----------|
| **漏洞类型** | 命令注入（CWE-78） |
| **严重等级** | 高危 |
| **检测工具** | semgrep / bandit |
| **漏洞数量** | 5 处 |
| **漏洞位置** | `ping_host()` os.system拼接、`check_port()` os.popen拼接、`lookup_domain()` subprocess shell=True、`compress_file()` os.system拼接、`get_network_info()` os.popen拼接 |
| **关键规则** | bandit: B602 (subprocess_popen_with_shell_equals_true), B605 (start_process_with_a_shell), semgrep: python.lang.security.audit.dangerous-system-call |
| **修复建议** | 使用 subprocess 不带 shell=True，使用参数列表而非字符串，对输入进行白名单验证 |
| **置信度** | ≥ 90% |

### 3. python_hardcoded_key.py — 硬编码密钥

| 项目 | 预期结果 |
|------|----------|
| **漏洞类型** | 硬编码凭证（CWE-798）/ 硬编码加密密钥（CWE-321） |
| **严重等级** | 高危 |
| **检测工具** | semgrep / bandit |
| **漏洞数量** | 8+ 处 |
| **漏洞位置** | AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, STRIPE_API_KEY, SENDGRID_API_KEY, DB_PASSWORD, ENCRYPTION_KEY, JWT_SECRET, AES_KEY |
| **关键规则** | bandit: B105 (hardcoded_password_string), B106 (hardcoded_password_func_arg), semgrep: python.lang.security.audit.hardcoded-secrets |
| **修复建议** | 使用环境变量或密钥管理服务存储敏感信息，使用 .env 文件（不提交到 Git），使用 Vault 等密钥管理工具 |
| **置信度** | ≥ 85% |

### 4. java_path_traversal.java — 路径遍历

| 项目 | 预期结果 |
|------|----------|
| **漏洞类型** | 路径遍历（CWE-22） |
| **严重等级** | 高危 |
| **检测工具** | semgrep |
| **漏洞数量** | 5+ 处 |
| **漏洞位置** | `doGet()` request.getParameter直接拼接、`readFileContent()` 直接使用用户路径、`getLogContent()` 日志名拼接、`getFileInfo()` 路径拼接、`deleteFile()` 文件名拼接、`copyFile()` 源和目标路径拼接 |
| **关键规则** | semgrep: java.lang.security.audit.path-traversal |
| **修复建议** | 验证路径在允许的目录内，使用 Path.resolve() + normalize()，过滤 ".." 遍历符，使用白名单验证文件名 |
| **置信度** | ≥ 85% |

### 5. javascript_xss.js — XSS

| 项目 | 预期结果 |
|------|----------|
| **漏洞类型** | 跨站脚本攻击 XSS（CWE-79） |
| **严重等级** | 中高危 |
| **检测工具** | semgrep |
| **漏洞数量** | 7+ 处 |
| **漏洞位置** | `displaySearchResults()` innerHTML拼接、`loadComments()` innerHTML拼接、`displayUserProfile()` innerHTML拼接、`appendChatMessage()` innerHTML拼接、`renderFromURL()` innerHTML拼接、`showError()` innerHTML拼接 |
| **关键规则** | semgrep: javascript.lang.security.audit.detect-xss |
| **修复建议** | 使用 textContent 代替 innerHTML，使用 DOM API 创建元素，对用户输入进行 HTML 转义，使用 CSP 策略 |
| **置信度** | ≥ 85% |

---

## 二、恶意代码分析样本预期结果

### 1. pe_downloader_sim.py — PE 下载器模拟

| 项目 | 预期结果 |
|------|----------|
| **判定结果** | 恶意（模拟） |
| **恶意类型** | 下载器/投放器（Downloader/Dropper） |
| **置信度** | ≥ 80% |
| **关键行为** | 远程下载文件、执行下载的文件、注册表持久化、C2 通信 |
| **IOC 指标** | 域名: malware-c2.example.com, URL: http://malware-c2.example.com/payload.exe, http://malware-c2.example.com/gate.php |
| **ATT&CK 映射** | T1105（远程文件下载）、T1059（命令执行）、T1547（注册表自启动）、T1071（应用层协议通信） |
| **YARA 匹配** | 可匹配通用下载器规则 |
| **文件特征** | 模拟导入 urlmon.dll, shell32.dll, kernel32.dll, advapi32.dll, wininet.dll |

### 2. pe_keylogger_sim.py — PE 键盘记录器模拟

| 项目 | 预期结果 |
|------|----------|
| **判定结果** | 恶意（模拟） |
| **恶意类型** | 键盘记录器（Keylogger） |
| **置信度** | ≥ 80% |
| **关键行为** | 安装全局键盘钩子、捕获按键、窃取剪贴板、数据外传、持久化 |
| **IOC 指标** | 域名: keylog-c2.example.com, URL: http://keylog-c2.example.com/upload.php, 文件: system_log.dat, svchost_update.exe |
| **ATT&CK 映射** | T1056.001（键盘记录）、T1115（剪贴板数据）、T1547（注册表自启动）、T1071（C2 通信）、T1029（定期数据外传） |
| **YARA 匹配** | Keylogger_Generic, HKS_Keylogger |
| **文件特征** | 模拟导入 user32.dll (SetWindowsHookEx, GetAsyncKeyState), kernel32.dll, advapi32.dll, gdi32.dll |

### 3. vba_macro_sim.vbs — VBA 宏模拟

| 项目 | 预期结果 |
|------|----------|
| **判定结果** | 恶意（模拟） |
| **恶意类型** | 恶意宏（Malicious Macro） |
| **置信度** | ≥ 85% |
| **关键行为** | AutoOpen 自动执行、PowerShell 下载执行、WScript.Shell 命令执行、反沙箱检测、痕迹清理 |
| **IOC 指标** | URL: http://malware-c2.example.com/payload.exe, 文件: update.exe |
| **ATT&CK 映射** | T1566.001（鱼叉式钓鱼附件）、T1059.005（Visual Basic 执行）、T1204.002（用户执行恶意文件）、T1071.001（HTTP C2）、T1027（混淆文件/信息） |
| **可疑关键词** | AutoOpen, CreateObject("WScript.Shell"), powershell -exec bypass, cmd.exe, IEX, DownloadString |
| **文件特征** | 包含宏自动执行入口、Shell 命令构造、环境变量访问 |

### 4. js_info_stealer_sim.js — 信息窃取脚本模拟

| 项目 | 预期结果 |
|------|----------|
| **判定结果** | 恶意（模拟） |
| **恶意类型** | 信息窃取器（Info Stealer） |
| **置信度** | ≥ 80% |
| **关键行为** | 代码混淆、Cookie 窃取、localStorage 窃取、表单数据窃取、系统信息收集、数据外传、反调试 |
| **IOC 指标** | 域名: stealer-c2.example.com, URL: http://stealer-c2.example.com/api/collect, ws://stealer-c2.example.com/ws |
| **ATT&CK 映射** | T1059.007（JavaScript 执行）、T1119（自动化数据收集）、T1537（数据外传）、T1185（浏览器会话劫持）、T1140（去混淆/解码） |
| **可疑模式** | document.cookie, localStorage, eval(), Function(), atob(), btoa(), 混淆变量名 |
| **文件特征** | 变量名混淆、控制流混淆、Base64 编码、多种外传通道 |

### 5. python_reverse_shell_sim.py — 反弹 Shell 模拟

| 项目 | 预期结果 |
|------|----------|
| **判定结果** | 恶意（模拟） |
| **恶意类型** | 反弹 Shell / 远程访问木马（RAT） |
| **置信度** | ≥ 85% |
| **关键行为** | 反向连接 C2、命令执行、Base64 编码载荷、PowerShell 反弹 Shell、无文件执行、权限提升、横向移动 |
| **IOC 指标** | 域名: attacker.example.com, IP: 10.0.0.1, 192.168.100.100, 端口: 4444, 8080, 443 |
| **ATT&CK 映射** | T1059.006（Python 执行）、T1059.001（PowerShell 执行）、T1071.001（HTTP C2）、T1055（进程注入）、T1021.002（SMB 远程服务）、T1548.002（UAC 绕过）、T1550.002（Pass-the-Hash） |
| **YARA 匹配** | ReverseShell_Generic, Python_RevShell, PS_Remote_Shell |
| **文件特征** | socket + subprocess 组合、os.dup2 重定向、Base64 编码载荷、shell=True 调用 |

---

## 三、正常对照样本预期结果

### 1. python_safe_query.py — 安全的参数化查询

| 项目 | 预期结果 |
|------|----------|
| **判定结果** | 安全 |
| **漏洞数量** | 0 |
| **检测工具** | semgrep / bandit |
| **预期行为** | 不应报告 SQL 注入漏洞 |
| **安全措施** | 全部使用参数化查询（? 占位符）、输入类型验证、密码哈希处理、上下文管理器管理连接 |
| **误报风险** | 低（bandit 可能对密码哈希操作报低级别提示，但非真正漏洞） |

### 2. javascript_safe_dom.js — 安全的 DOM 操作

| 项目 | 预期结果 |
|------|----------|
| **判定结果** | 安全 |
| **漏洞数量** | 0 |
| **检测工具** | semgrep |
| **预期行为** | 不应报告 XSS 漏洞 |
| **安全措施** | 全部使用 textContent 代替 innerHTML、使用 DOM API 创建元素、提供 HTML 转义工具函数 |
| **误报风险** | 极低 |

### 3. python_file_handler.py — 安全的文件处理

| 项目 | 预期结果 |
|------|----------|
| **判定结果** | 安全 |
| **漏洞数量** | 0 |
| **检测工具** | semgrep / bandit |
| **预期行为** | 不应报告路径遍历漏洞 |
| **安全措施** | 路径验证（resolve + relative_to）、扩展名白名单、文件大小限制、文件名清理、路径遍历符过滤 |
| **误报风险** | 低 |

---

## 四、验证标准

### 准确率计算

- **检出率（True Positive Rate）**：漏洞/恶意样本被正确检出的比例，目标 ≥ 80%
- **误报率（False Positive Rate）**：正常样本被错误标记为有问题的比例，目标 ≤ 10%
- **置信度**：Agent 分析结果的可信程度，目标平均 ≥ 80%

### 验证方法

1. 将每个样本提交给 SecAgent 进行分析
2. 对比 Agent 输出与本文档的预期结果
3. 记录：是否检出、检出漏洞类型是否正确、置信度是否达标、修复建议是否合理
4. 对于恶意样本：IOC 提取是否完整、ATT&CK 映射是否准确
5. 对于正常样本：是否产生误报

### 可接受的偏差

- 漏洞数量：预期 ±2 以内
- 严重等级：允许上下浮动一级
- ATT&CK 映射：允许缺少 1-2 个技术，但核心技术必须识别
- 置信度：允许低于预期 10% 以内
