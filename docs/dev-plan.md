# SecAgent 开发实施文档

> 基于 [plan.md](plan.md) 细化，作为团队开发全程跟踪清单。
> 完成一项勾一项，每个任务标注了**负责人**和**预计耗时**。

---

## 目录

- [第1周：基础搭建](#第1周基础搭建)
- [第2周：Agent引擎 + 工具链启动](#第2周agent引擎--工具链启动)
- [第3周：Agent完成 + 工具链收尾 + 后端API启动](#第3周agent完成--工具链收尾--后端api启动)
- [第4周：后端收尾 + 前端启动](#第4周后端收尾--前端启动)
- [第5周：前端收尾 + 联调测试](#第5周前端收尾--联调测试)
- [第6周：打磨 + 文档 + 交付](#第6周打磨--文档--交付)
- [附录：接口约定清单](#附录接口约定清单)
- [附录：演示样本清单](#附录演示样本清单)

---

## 第1周：基础搭建

> **目标**：环境就绪、接口约定完成、脚手架可运行
> **里程碑 M1**：前后端可通信，Docker 一键启动

### 1.1 项目初始化（全员参与，第1-2天）

- [X] `[全员]` 创建 Git 私有仓库，确定 `.gitignore`，提交初始 commit
- [X] `[全员]` 确定项目目录结构（按 plan.md 附录A），创建所有空目录和 `__init__.py`
- [X] `[全员]` 每人克隆仓库，确认能正常 push/pull

### 1.2 开发环境搭建（各成员并行，第1-2天）

- [X] `[全员]` 安装 Docker Desktop，验证 `docker compose version`
- [X] `[C]` 创建 `backend/requirements.txt`，包含所有 Python 依赖
- [X] `[C]` 创建 `backend/requirements.txt`：fastapi, uvicorn, websockets, httpx, sqlalchemy, python-multipart, reportlab, pefile, yara-python
- [X] `[D]` 使用 Vite 创建 React + TypeScript 项目：`npm create vite@latest frontend -- --template react-ts`
- [X] `[D]` 安装前端依赖：`npm install antd echarts echarts-for-react react-router-dom react-markdown highlight.js`
- [X] `[C]` 创建 `docker-compose.yml`（前端 Nginx + 后端 Uvicorn + Redis）
- [X] `[全员]` 验证 `docker compose up` 后前后端均可访问

### 1.3 数据库设计（成员 C，第2-3天）

- [X] `[C]` 设计 `task` 表：id, type(漏洞检测/恶意分析), status, input_path, input_content, result_json, created_at, updated_at
- [X] `[C]` 设计 `analysis_step` 表：id, task_id, step_num, thought, action, observation, created_at
- [X] `[C]` 设计 `conversation` 表：id, task_id, role, content, created_at
- [X] `[C]` 编写 SQLAlchemy 模型代码（`backend/app/models/`）
- [X] `[C]` 编写数据库初始化脚本，提交后可跑通

### 1.4 API Key 申请（成员 A，第2天）

- [X] `[A]` 注册 DeepSeek 开发者账号，申请 API Key
- [X] `[A]` 测试 API Key 可用性：写一个简单脚本调用 chat/completions
- [ ] `[A]` 将 API Key 配置在 `.env` 文件中（不提交到 Git）
- [X] `[C]` 创建 `.env.example` 模板文件提交到仓库

### 1.5 知识库数据准备（成员 B，第 2-3 天）

- [x] `[B]` 下载 MITRE CWE 列表 JSON，存入 `backend/data/cwe.json`
- [x] `[B]` 下载 MITRE ATT&CK Enterprise STIX 数据，存入 `backend/data/attack.json`
- [x] `[B]` 编写 CWE 数据加载/查询脚本（按 ID 查询名称和描述）
- [x] `[B]` 编写 ATT&CK 数据加载/查询脚本（按技术 ID 查询名称和战术）
- [x] `[B]` 收集/编写 5+ 条常用 YARA 规则，存入 `backend/data/yara_rules/`
- [x] `[B]` 写测试脚本验证所有数据文件可正确加载

### 1.6 接口规范约定（全员参与，第3-4天）

- [ ] `[A]+[B]` 约定**工具 Schema 标准格式**（JSON 结构：name, description, parameters）
- [ ] `[A]+[C]` 约定**分析结果 JSON 结构**（vulnerabilities 数组、malware_analysis 对象等）
- [ ] `[A]+[D]` 约定**WebSocket 消息格式**（type: thought/action/observation/done/error）
- [ ] `[C]+[D]` **FastAPI 自动生成 Swagger 文档**，作为前后端接口契约
- [ ] `[全员]` 将上述约定写入 `docs/接口规范.md` 并提交

### 1.7 脚手架验证（全员，第4-5天）

- [ ] `[C]` 实现 FastAPI 根路由 `/` 和健康检查 `/health`
- [ ] `[C]` 实现第一个 API：`POST /api/tasks`（仅创建空任务，返回 task_id）
- [ ] `[D]` 实现 React 首页（仅显示 "SecAgent" 标题 + Ant Design 布局框架）
- [ ] `[D]` 从首页调用 `/api/tasks` 验证前后端通信（即使返回空列表）
- [ ] `[A]` 写一个最小 LLM 调用脚本：发送消息给 DeepSeek，打印回复
- [ ] `[B]` 写一个最小 semgrep 调用脚本：扫描一段 Python 代码，打印结果
- [ ] `[全员]` Docker Compose 一键启动全栈验证通过 ✅

---

## 第2周：Agent引擎 + 工具链启动

> **目标**：Agent 核心可跑通命令行 Demo，工具链完成基础集成

### 2.1 LLM API 封装（成员 A，第1-3天）

- [ ] `[A]` 实现 `LLMClient` 类（同步调用）：传入 messages，返回 response
- [ ] `[A]` 实现 `LLMClient` 类（流式调用）：传入 messages，yield 逐 token 返回
- [ ] `[A]` 实现 Function Calling 支持：传入 tools 列表，解析返回的 tool_calls
- [ ] `[A]` 实现错误处理：API 超时重试（3次）、Token 超限截断、网络异常兜底
- [ ] `[A]` 实现 Token 计数器：估算每次调用的 Token 消耗
- [ ] `[A]` 写单元测试：同步调用返回正确格式、流式调用能拿到完整结果

### 2.2 System Prompt 编写（成员 A，第1-2天）

- [ ] `[A]` 编写代码漏洞检测的 System Prompt（`backend/app/agent/prompts/code_audit.txt`）
- [ ] `[A]` 编写恶意代码分析的 System Prompt（`backend/app/agent/prompts/malware_analysis.txt`）
- [ ] `[A]` Prompt 包含：角色定位、工具清单及说明、输出格式要求、安全约束
- [ ] `[A]` 用 2 个测试样本验证 Prompt 效果，调整至行为符合预期

### 2.3 Function Calling Schema 定义（成员 A + B，第2-3天）

- [ ] `[A]+[B]` 定义 `scan_code` 工具 Schema（代码静态扫描）
- [ ] `[A]+[B]` 定义 `query_cve` 工具 Schema（CVE 漏洞库查询）
- [ ] `[A]+[B]` 定义 `query_threat_intel` 工具 Schema（威胁情报查询）
- [ ] `[A]+[B]` 定义 `extract_file_features` 工具 Schema（文件特征提取）
- [ ] `[A]+[B]` 定义 `extract_iocs` 工具 Schema（IOC 提取）
- [ ] `[A]+[B]` 定义 `map_attack` 工具 Schema（ATT&CK 技术映射）
- [ ] `[A]` 将所有 Schema 注册到工具注册器（`ToolRegistry`）

### 2.4 ReAct 循环实现（成员 A，第3-5天）

- [ ] `[A]` 实现 `AgentEngine` 类：接收任务，启动 ReAct 循环
- [ ] `[A]` 实现 Thought 阶段：LLM 分析状态，输出推理文本
- [ ] `[A]` 实现 Action 阶段：解析 LLM 的 tool_calls，调度工具执行
- [ ] `[A]` 实现 Observe 阶段：将工具返回结果格式化后反馈给 LLM
- [ ] `[A]` 实现循环控制：最多 10 步、单步超时 60s、重复动作检测
- [ ] `[A]` 实现兜底逻辑：连续 3 步无进展 → 切换为标准分析流程
- [ ] `[A]` 命令行 Demo：输入一段有漏洞的 Python 代码 → Agent 自动分析 → 打印结果

### 2.5 WebSocket 实时推送（成员 A + C，第4-5天）

- [ ] `[C]` 实现 WebSocket 端点：`ws://localhost:8000/ws/{task_id}`
- [ ] `[A]` ReAct 每一步通过回调函数推送状态更新
- [ ] `[A]` 推送数据结构：`{type: "thought"|"action"|"observation"|"done"|"error", data: {...}}`
- [ ] `[C]` WebSocket 连接管理：心跳检测、断线重连、任务结束自动关闭

### 2.6 静态分析工具集成（成员 B，第2-5天）

- [ ] `[B]` 安装并验证 semgrep CLI 可用：`semgrep --version`
- [ ] `[B]` 实现 `run_semgrep(code, language)` 函数：写入临时文件 → semgrep 扫描 → 解析 JSON 输出
- [ ] `[B]` 安装并验证 bandit CLI 可用：`bandit --version`
- [ ] `[B]` 实现 `run_bandit(code)` 函数（仅 Python 代码）
- [ ] `[B]` 实现扫描结果标准化：统一为 `{rule_id, severity, file, line, message, code_snippet}` 格式
- [ ] `[B]` 实现 `scan_code` 工具入口函数：根据 language 参数分发到 semgrep/bandit
- [ ] `[B]` 写测试：扫描含 SQL 注入的 Python 代码 → semgrep 应检出

### 2.7 漏洞库查询工具（成员 B，第3-5天）

- [ ] `[B]` 注册 NVD API Key（https://nvd.nist.gov/developers/request-an-api-key）
- [ ] `[B]` 实现 `query_cve_by_id(cve_id)` 函数：查询单个 CVE 详情
- [ ] `[B]` 实现 `query_cve_by_keyword(keyword)` 函数：按关键字搜索 CVE
- [ ] `[B]` 实现 CWE 本地查询：`query_cwe(cwe_id)` → 返回名称+描述+缓解措施
- [ ] `[B]` 实现 `query_cve` 工具入口函数：支持按 CVE ID 或关键字查询
- [ ] `[B]` 写测试：查询 CVE-2021-44228 → 应返回 Log4Shell 详情

### 2.8 威胁情报查询工具（成员 B，第4-5天）

- [ ] `[B]` 注册 AlienVault OTX API Key（免费）
- [ ] `[B]` 实现 `query_otx_ip(ip)` / `query_otx_domain(domain)` / `query_otx_hash(hash)`
- [ ] `[B]` 实现 `query_urlhaus(url)`：查询 URLhaus 恶意 URL 数据库
- [ ] `[B]` 实现 `query_threat_intel` 工具入口函数：自动判断 IOC 类型并调用对应 API
- [ ] `[B]` 实现 API 调用失败降级（返回本地缓存数据或"查询失败"提示）

---

## 第3周：Agent完成 + 工具链收尾 + 后端API启动

> **目标**：Agent 引擎完整可用，工具链全部可被 Agent 调用，后端 API 框架就绪
> **里程碑 M2**：Agent 可自主完成一次完整代码漏洞分析（命令行）

### 3.1 Agent 引擎完善（成员 A，第1-3天）

- [ ] `[A]` 实现任务类型自动识别：根据输入自动判断是代码漏洞检测还是恶意分析
- [ ] `[A]` 实现分析结果聚合：从多步工具调用结果中提取关键发现
- [ ] `[A]` 实现置信度计算：根据工具结果一致性和 LLM 自身判断计算置信度
- [ ] `[A]` 实现标准分析流程 fallback（当 Agent 自主决策失败时使用）
- [ ] `[A]` Agent 命令行 Demo 2.0：上传恶意脚本 → 自动分析 → 输出判定+依据
- [ ] `[A]` 用 5 个样本测试 Agent，记录准确率和 Token 消耗

### 3.2 Prompt 调优（成员 A，第3-5天，贯穿后续）

- [ ] `[A]` 准备 3 个标准测试样本（已知漏洞代码、正常代码、恶意脚本）
- [ ] `[A]` 对每个样本测试当前 Prompt 效果，记录问题
- [ ] `[A]` 调整 System Prompt：补充输出格式示例（Few-shot）
- [ ] `[A]` 调整工具描述文案：使 LLM 更准确地选择工具
- [ ] `[A]` 添加约束规则：禁止跳过工具直接下结论、必须引用证据
- [ ] `[A]` 对比调整前后的分析质量，记录改进

### 3.3 文件特征提取工具（成员 B，第1-3天）

- [ ] `[B]` 安装 pefile：`pip install pefile`
- [ ] `[B]` 实现 PE 文件分析：导入表提取、节区信息、编译时间戳
- [ ] `[B]` 实现文件字符串提取：提取所有可打印字符串（≥4 字符）
- [ ] `[B]` 实现 Office 文档分析：检测宏、提取 VBA 代码
- [ ] `[B]` 实现文件类型自动识别（基于 magic bytes，不依赖扩展名）
- [ ] `[B]` 实现 `extract_file_features` 工具入口函数：返回文件基本信息+特征
- [ ] `[B]` 写测试：上传 benign.exe → 应返回正确的导入表信息

### 3.4 IOC 提取 + ATT&CK 映射工具（成员 B，第2-4天）

- [ ] `[B]` 实现正则 IOC 提取：IPv4、域名、URL、MD5/SHA1/SHA256 Hash
- [ ] `[B]` 实现 `extract_iocs` 工具入口函数：输入文本 → 返回分类 IOC 列表
- [ ] `[B]` 实现 ATT&CK 技术映射：根据恶意行为关键词匹配 ATT&CK 技术 ID
- [ ] `[B]` 实现 `map_attack` 工具入口函数：输入行为描述 → 返回技术 ID+战术+名称
- [ ] `[B]` 写测试：输入"credential dumping"→ 应匹配到 T1003

### 3.5 YARA 规则集成（成员 B，第3-4天）

- [ ] `[B]` 准备 10+ 条常用 YARA 规则（覆盖常见恶意家族）
- [ ] `[B]` 实现 `scan_yara(file_path)` 函数：加载规则 → 扫描文件 → 返回匹配规则
- [ ] `[B]` 将 YARA 扫描集成到 `extract_file_features` 中作为子功能
- [ ] `[B]` 写测试：用已知恶意样本的 Hash 验证 YARA 规则可编译通过

### 3.6 工具层整体联调（成员 B，第4-5天）

- [ ] `[B]` 确保所有工具入口函数签名统一：`tool_name(**params) -> dict`
- [ ] `[B]` 确保所有工具返回格式符合约定的 Tool Schema
- [ ] `[B]` 编写工具层集成测试：模拟 Agent 依次调用所有工具
- [ ] `[B]` 与成员 A 联调：Agent 通过 Function Calling 调用 B 的工具确认可正常返回

### 3.7 后端 API 开发（成员 C，第2-5天）

- [ ] `[C]` 实现 `POST /api/tasks`：创建分析任务，存入数据库，返回 task_id
- [ ] `[C]` 实现 `GET /api/tasks/{task_id}`：查询任务状态和结果
- [ ] `[C]` 实现 `GET /api/tasks`：查询历史任务列表（支持分页+筛选）
- [ ] `[C]` 实现 `POST /api/tasks/{task_id}/chat`：发送追问消息，返回 Agent 回复
- [ ] `[C]` 实现 `GET /api/tasks/{task_id}/report/pdf`：触发 PDF 报告生成并下载
- [ ] `[C]` 实现文件上传端点：`POST /api/upload`（类型检查+大小限制+临时存储）
- [ ] `[C]` 实现 API 层安全措施：CORS 配置、输入验证（Pydantic）、速率限制

### 3.8 报告生成引擎（成员 C，第4-5天）

- [ ] `[C]` 设计 Markdown 报告模板（漏洞检测版）：`backend/app/report/templates/vuln_report.md`
- [ ] `[C]` 设计 Markdown 报告模板（恶意分析版）：`backend/app/report/templates/malware_report.md`
- [ ] `[C]` 实现报告渲染函数：将分析结果 JSON 填入模板 → 生成 Markdown 文本
- [ ] `[C]` 实现 PDF 导出：使用 WeasyPrint 或 ReportLab 将 Markdown 转 PDF
- [ ] `[C]` 测试：提交一个分析结果 JSON → 生成完整 Markdown 报告和 PDF

---

## 第4周：后端收尾 + 前端启动

> **目标**：后端 API 完整可用，前端核心页面完成
> **里程碑 M3**：所有 API 可用，所有工具可被 Agent 调用

### 4.1 后端完善与收尾（成员 C，第1-2天）

- [ ] `[C]` 实现对话管理模块：存储/加载对话历史、上下文窗口管理
- [ ] `[C]` 实现 AI 报告摘要生成：调用 LLM 将分析结果凝练为摘要
- [ ] `[C]` 实现分析结果智能排序：按危险等级/置信度排序
- [ ] `[C]` 实现文件上传安全控制：类型白名单校验、大小限制（50MB）、文件 Hash 记录
- [ ] `[C]` 实现临时文件清理：分析完成后自动删除临时文件
- [ ] `[C]` API 全部可用验证：用 Postman 或 curl 逐个测试所有端点

### 4.2 任务队列管理（成员 C，第2-3天）

- [ ] `[C]` 方案选择：如果 Redis 可用则用 Celery，否则用 Python `threading` 实现简易异步队列
- [ ] `[C]` 实现任务状态机：pending → analyzing → done / failed
- [ ] `[C]` 实现并发控制：同时最多处理 3 个分析任务
- [ ] `[C]` API `GET /api/tasks/{task_id}` 实时返回当前状态和已完成步骤

### 4.3 前端项目搭建（成员 D，第1-2天）

- [ ] `[D]` 确认 React 项目结构：pages / components / hooks / services / utils
- [ ] `[D]` 配置 React Router：`/`、`/submit`、`/analysis/:taskId`、`/report/:taskId`、`/history`
- [ ] `[D]` 配置 Ant Design 全局主题（深色安全主题风格：深蓝底色+绿/红色点缀）
- [ ] `[D]` 封装 API 请求模块：`frontend/src/services/api.ts`（axios 实例+拦截器）
- [ ] `[D]` 封装 WebSocket 连接 Hook：`useWebSocket(taskId)` → 自动连接/重连/返回最新状态

### 4.4 仪表盘首页（成员 D，第2-3天）

- [ ] `[D]` 实现首页统计卡片：今日任务数、总任务数、高危发现数、平均耗时
- [ ] `[D]` 实现最近分析列表：展示最近 5 个任务（类型+状态+时间）
- [ ] `[D]` 实现快捷操作入口：代码扫描、恶意分析两个大按钮
- [ ] `[D]` 首页数据全部通过 API 从后端实时获取

### 4.5 任务提交页面（成员 D，第3-4天）

- [ ] `[D]` 实现"代码漏洞检测"Tab：代码编辑区（带语法高亮）、语言选择下拉框、粘贴/上传切换
- [ ] `[D]` 实现"恶意代码分析"Tab：拖拽上传区域、文件信息预览、支持多文件类型
- [ ] `[D]` 实现提交按钮 + 防重复提交 + 提交成功跳转到分析页面
- [ ] `[D]` 实现文件上传进度条 + 上传完成反馈

### 4.6 分析过程页 — 思维链展示（成员 D，第4-5天）

- [ ] `[D]` 设计"思维链卡片"组件：Thought（💭蓝色）、Action（🔧橙色）、Observation（👁绿色）、Done（✅）、Error（❌红色）
- [ ] `[D]` 实现卡片渐入动画：每张卡片从底部滑入（CSS transition + 延时）
- [ ] `[D]` 实现正在执行的步骤：脉动动画（pulse）+ "分析中..."文字
- [ ] `[D]` 实现步骤展开/折叠：点击可查看工具调用的详细参数和返回结果
- [ ] `[D]` 实现分析进度条：显示已完成步骤/总步骤（预估）
- [ ] `[D]` 实现分析完成 → 自动跳转报告页，或手动点击"查看报告"按钮

---

## 第5周：前端收尾 + 联调测试

> **目标**：全流程跑通，系统稳定可用
> **里程碑 M4**：前端到后端完整流程（提交→分析→思维链→报告→PDF导出）

### 5.1 报告展示页面（成员 D，第1-2天）

- [ ] `[D]` 实现报告基本信息区：分析时间、目标文件/代码名、分析耗时、风险等级徽标
- [ ] `[D]` 实现漏洞列表组件：Ant Design Table + 危险等级颜色标签 + CWE 编号链接
- [ ] `[D]` 实现漏洞详情展开行：代码片段（语法高亮）+ 修复建议
- [ ] `[D]` 实现恶意分析结果组件：判定结果大标识（红/黄/绿）+ 置信度占比 + 行为描述
- [ ] `[D]` 实现 IOC 清单表格：类型图标 + 值 + 威胁情报查询结果（已知恶意/未知）
- [ ] `[D]` 实现 ATT&CK 技术映射展示：Tag 标签 + 战术阶段标注
- [ ] `[D]` 实现 Markdown 全文预览 Tab
- [ ] `[D]` 实现 PDF 下载按钮 + 下载进度

### 5.2 可视化图表（成员 D，第2-3天）

- [ ] `[D]` 实现风险雷达图组件：多维度安全评分（代码质量、认证、授权、数据保护、加密、日志）
- [ ] `[D]` 实现漏洞类型分布饼图/环形图（ECharts）
- [ ] `[D]` 实现 ATT&CK 热力图组件：用 ECharts Heatmap 展示战术×技术矩阵
- [ ] `[D]` 实现漏洞严重等级柱状图：高危/中危/低危/信息
- [ ] `[D]` 图表支持响应式、支持导出为图片、配色与主题一致

### 5.3 交互式对话面板（成员 D，第3天）

- [ ] `[D]` 实现分析报告页底部对话面板：气泡式聊天界面
- [ ] `[D]` 实现追问输入框 + 发送按钮，支持 Shift+Enter 换行
- [ ] `[D]` 实现 Agent 回复气泡：打字动画效果 + Markdown 渲染
- [ ] `[D]` 实现对话历史显示（按时间排序）
- [ ] `[D]` 对话内容通过 API 发送到后端，后端调用 Agent 并返回回复

### 5.4 历史任务管理页（成员 D，第4天）

- [ ] `[D]` 实现任务列表页：Ant Design Table + 分页
- [ ] `[D]` 实现搜索框：按任务类型/状态/时间范围筛选
- [ ] `[D]` 实现每行操作按钮：查看报告、删除任务
- [ ] `[D]` 实现删除确认弹窗（Ant Design Modal）

### 5.5 前后端联调（全员，第4-5天）

- [ ] `[全员]` 代码漏洞检测全流程联调：提交代码 → Agent 分析 → 思维链展示 → 报告展示 → PDF 导出
- [ ] `[全员]` 恶意代码分析全流程联调：上传文件 → Agent 分析 → 结果展示 → IOC 清单 → PDF 导出
- [ ] `[C]+[D]` 验证 WebSocket 实时推送：思维链各步骤能逐条展示、无丢失、无乱序
- [ ] `[C]+[D]` 验证错误处理：文件上传超大 → 提示限制、API 超时 → 友好提示、网络断开 → 重连
- [ ] `[C]+[D]` 验证对话追问功能：发送问题 → 显示回复 → 多轮对话正常

### 5.6 测试样本准备（成员 B，第3-5天）

- [ ] `[B]` 准备 5 个漏洞代码样本（Python 3个 + Java 1个 + JavaScript 1个）
- [ ] `[B]` 包含漏洞类型：SQL注入、XSS、命令注入、路径遍历、硬编码密钥
- [ ] `[B]` 准备 5 个恶意代码样本（PE 2个 + 脚本 2个 + Office宏 1个）
- [ ] `[B]` 样本需安全无害（仅用于演示，不含真实恶意功能）
- [ ] `[B]` 为每个样本编写"预期分析结果"文档，用于对比验证
- [ ] `[B]` 准备 3 个正常样本（对照：确认不会误报）

### 5.7 系统测试与优化（全员，第5天）

- [ ] `[A]` 用 10 个样本测试 Agent 分析准确率，记录漏报/误报情况
- [ ] `[A]` 优化 Prompt，针对测试中发现的问题调整
- [ ] `[C]` 测试分析耗时：单任务控制在 3 分钟内
- [ ] `[D]` 测试前端性能：页面加载 < 3 秒、思维链动画流畅（无卡顿）
- [ ] `[全员]` Bug Bash：1 小时内全员自由测试，集中发现和修复问题
- [ ] `[C]` 修复所有已知 Bug，整理 Issue 清单

---

## 第6周：打磨 + 文档 + 交付

> **目标**：精美好用、文档齐全、演示流畅
> **里程碑 M5**：项目正式交付

### 6.1 UI/UX 打磨（成员 D，第1-3天）

- [ ] `[D]` 统一配色方案：确认深色主题全局生效，调整对比度和可读性
- [ ] `[D]` 优化移动端/小屏幕响应式布局
- [ ] `[D]` 添加全局 Loading 状态 + 骨架屏（Skeleton）
- [ ] `[D]` 优化思维链动画时长和缓动曲线（不要太慢也不要太快）
- [ ] `[D]` 添加页面切换过渡动画
- [ ] `[D]` 添加空状态插图（无任务时、无结果时）
- [ ] `[D]` 添加 404 页面
- [ ] `[D]` 审查所有文案：无错别字、术语统一、表达清晰

### 6.2 功能收尾（成员 A + C，第1-2天）

- [ ] `[A]` Token 消耗统计与展示（每个任务/总计）
- [ ] `[C]` 最终确认所有分析后临时文件被清理
- [ ] `[C]` Docker Compose 最终验证：全新机器 clone → `docker compose up` → 可运行
- [ ] `[A]` 环境变量检查：所有敏感信息在 `.env`，`.env.example` 更新
- [ ] `[C]` README.md 编写：项目简介、快速开始、技术栈、目录结构、环境变量说明

### 6.3 项目报告撰写（全员参与，第2-4天）

- [ ] `[全员]` 确定报告大纲和分工：
  - 第1章 绪论（项目背景、目的意义）→ `[A]`
  - 第2章 相关技术综述（LLM、ReAct、安全工具）→ `[A]+[B]`
  - 第3章 系统需求分析（功能需求、用例）→ `[全员]`
  - 第4章 系统设计（架构、数据库、接口、Agent设计）→ `[C]`
  - 第5章 系统实现（各模块实现细节、关键代码）→ `[全员各自写自己的模块]`
  - 第6章 系统测试（测试用例、测试结果、性能）→ `[B]`
  - 第7章 总结与展望 → `[A]`
- [ ] `[全员]` 各自撰写负责章节，统一格式和风格
- [ ] `[A]` 整合各章节，统一排版、图表编号、参考文献格式
- [ ] `[全员]` 交叉审阅，提出修改意见
- [ ] `[A]` 最终定稿，生成 PDF

### 6.4 PPT 制作（成员 D + A，第3-5天）

- [ ] `[D]` 设计 PPT 模板：统一配色、字体、版式
- [ ] `[D]` 制作封面页：项目名称、团队成员、指导教师
- [ ] 制作各章节幻灯片：
  - [ ] 项目背景与动机（1-2页）
  - [ ] 系统架构图（1页，使用架构图）
  - [ ] 核心技术亮点：ReAct Agent + Function Calling + 思维链可视化（2-3页）
  - [ ] 功能演示截图：代码漏洞检测流程（2-3页）
  - [ ] 功能演示截图：恶意代码分析流程（2-3页）
  - [ ] 团队分工与协作（1页）
  - [ ] 项目成果总结（1页）
  - [ ] Q&A（1页）
- [ ] `[D]` 嵌入关键截图和动图
- [ ] `[A]` 撰写演讲备注（Speaker Notes）

### 6.5 用户手册撰写（成员 C，第3-4天）

- [ ] `[C]` 编写系统部署指南（Docker Compose 部署步骤）
- [ ] `[C]` 编写使用说明：如何提交代码扫描、如何上传文件分析、如何查看报告、如何对话追问
- [ ] `[C]` 编写常见问题（FAQ）
- [ ] `[C]` 添加操作截图辅助说明

### 6.6 演示准备（全员，第4-6天）

- [ ] `[全员]` 设计演示脚本：
  1. 打开仪表盘首页（5秒）
  2. 提交一段有 SQL 注入的 Python 代码（30秒）
  3. 观看 Agent 思维链实时分析（60秒）
  4. 查看生成的漏洞报告 + 图表（30秒）
  5. 追问"修复方案"演示交互对话（30秒）
  6. 上传恶意 Office 宏文档分析（60秒）
  7. 查看恶意分析报告 + ATT&CK 热力图（30秒）
  8. PDF 导出（10秒）
  9. 总结（15秒）
     → 总时长约 5 分钟
- [ ] `[全员]` 排练 3 次以上，确保流畅、无卡顿、无 Bug
- [ ] `[全员]` 准备应急预案：API 超时怎么办、网络断了怎么办、现场环境怎么配置
- [ ] `[C]` 准备离线演示环境（确保不依赖外部网络也能展示部分功能，或准备录屏备选）

### 6.7 最终交付检查清单（全员，第6天）

- [ ] `[ ]` 源代码仓库完整、可 Clone 可运行
- [ ] `[ ]` `docker compose up` 一键启动成功
- [ ] `[ ]` README.md 清晰完整
- [ ] `[ ]` 项目报告 PDF 格式正确
- [ ] `[ ]` PPT 文件完整无缺失
- [ ] `[ ]` 用户手册 PDF 格式正确
- [ ] `[ ]` `.env.example` 包含所有需要的环境变量
- [ ] `[ ]` 无硬编码密钥/密码提交到仓库
- [ ] `[ ]` 所有依赖版本锁定（requirements.txt + package-lock.json）
- [ ] `[ ]` Git 提交历史完整、commit message 有意义
- [ ] `[ ]` 演示样本文件齐全
- [ ] `[ ]` 全流程至少完整跑通 3 次

---

## 附录：接口约定清单

> 第1周完成约定，开发过程中严格遵守

- [ ] 工具 Schema 标准格式（JSON）→ `[A]+[B]`
- [X] 数据库表结构 → `[C]`
- [ ] REST API 接口文档（Swagger 自动生成）→ `[C]`
- [ ] WebSocket 消息格式 → `[A]+[D]`
- [ ] 分析结果 JSON 结构 → `[A]+[C]`

---

## 附录：演示样本清单

> 第5周由成员 B 准备

### 漏洞检测样本（5个）

- [ ] Python — SQL 注入（字符串拼接查询）
- [ ] Python — 命令注入（os.system 拼接用户输入）
- [ ] Java — 路径遍历（未过滤的 file path）
- [ ] JavaScript — XSS（innerHTML 直接设置用户输入）
- [ ] Python — 硬编码密钥（API Key 明文写在代码中）

### 恶意分析样本（5个）

- [ ] PE 文件 — 模拟下载器（导入 URLDownloadToFile + ShellExecute）
- [ ] PE 文件 — 模拟键盘记录器（导入 SetWindowsHookEx）
- [ ] VBA 宏 — 模拟恶意宏（AutoOpen + URL 下载 + Shell 执行）
- [ ] JavaScript — 混淆的信息窃取脚本
- [ ] Python 脚本 — 模拟反弹 Shell

### 正常对照样本（3个）

- [ ] Python — 安全的参数化查询脚本
- [ ] JavaScript — 安全的 DOM 操作（使用 textContent）
- [ ] Python — 正常的文件处理工具

---

> **文档版本**：v1.0
> **编写日期**：2026-06-01
> **项目周期**：6周
> **团队**：4人
>
> **使用方式**：每个成员在开始一项任务前，找到对应的 checkbox；完成后勾选 `[x]`。每周开始前回顾本周任务，周末检查完成情况。Git commit 时可引用任务编号。
