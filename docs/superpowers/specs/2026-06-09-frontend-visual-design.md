# SecAgent 前端视觉设计规范

> 基于「清风白纸 + 奶白底」方案，为 SecAgent 全项目定义视觉风格。
> 本文档是所有前端页面的样式权威来源。

---

## 1. 设计哲学

**核心情绪**：安全是轻松的，Agent 智能且从容。

| 要 | 不要 |
|---|---|
| 大量留白，让内容呼吸 | 堆砌信息、填满每一寸空间 |
| 奶白底色营造温暖安心感 | 纯黑/深灰底色的「黑客风」 |
| 蓝绿渐变作为唯一视觉焦点 | 多色乱用、高饱和撞色 |
| 柔和圆角 + 毛玻璃 = 轻量感 | 锐利边角 + 硬阴影 = 沉重感 |
| 微动效传递「活」的感觉 | 静态死板或过度炫技动画 |
| 用图标和色彩层级区分状态 | 用大段红色/警告色制造焦虑 |

**三个关键词**：轻量（Light）、通透（Airy）、从容（Calm）

---

## 2. 色彩系统

### 2.1 背景色

| 用途 | 色值 | 说明 |
|---|---|---|
| 页面主背景 | `#FAF9F7` | 奶白色，微暖，不刺眼 |
| 卡片/面板背景 | `#FFFFFF` | 纯白，与背景形成微妙层次 |
| 悬浮/提升层背景 | `rgba(255,255,255,0.72)` | 毛玻璃基底色 |

### 2.2 主色调 — 蓝绿渐变

用于品牌标识、主按钮、关键交互元素。整站仅此一组渐变作为视觉锚点。

| 名称 | 色值 | 用途 |
|---|---|---|
| 渐变起点（天蓝） | `#5BA3FF` | 渐变左侧 / 单色引用时的首选 |
| 渐变终点（薄荷） | `#5EEAD4` | 渐变右侧 |
| 渐变方向 | `135deg` | `#5BA3FF → #5EEAD4` |

CSS 变量定义：
```css
--accent-start: #5BA3FF;
--accent-end: #5EEAD4;
--accent-gradient: linear-gradient(135deg, #5BA3FF 0%, #5EEAD4 100%);
```

### 2.3 文字色阶

| 层级 | 色值 | 用途 |
|---|---|---|
| 主文字 | `#1E293B` | 标题、正文 |
| 次文字 | `#64748B` | 描述、辅助信息 |
| 弱文字 | `#94A3B8` | 时间戳、占位符、禁用态 |
| 反白文字 | `#FFFFFF` | 渐变背景上的文字 |

### 2.4 语义色

用于状态标记，但需克制使用。以色点/色条/小标签形式出现，不大面积铺色。

| 语义 | 色值 | 场景 |
|---|---|---|
| 成功/安全 | `#10B981` | 分析完成、无风险 |
| 警告/中危 | `#F59E0B` | 需要关注 |
| 危险/高危 | `#EF4444` | 漏洞/恶意判定 |
| 信息/提示 | `#5BA3FF` | 一般性信息 |

### 2.5 边框与分割线

| 用途 | 色值 |
|---|---|
| 轻分割线 | `rgba(148,163,184,0.08)` |
| 常规边框 | `rgba(148,163,184,0.12)` |
| 强调边框（hover/focus） | `rgba(91,163,255,0.3)` |

### 2.6 阴影

| 层级 | 值 | 用途 |
|---|---|---|
| 微阴影 | `0 1px 3px rgba(0,0,0,0.04)` | 卡片默认态 |
| 轻阴影 | `0 4px 16px rgba(0,0,0,0.06)` | 卡片 hover |
| 浮阴影 | `0 8px 32px rgba(91,163,255,0.12)` | 主按钮、弹窗 |
| 品牌阴影 | `0 8px 32px rgba(91,163,255,0.25)` | 渐变元素（Logo、Hero 图标） |

---

## 3. 字体

### 3.1 字体栈

```css
--font-sans: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto,
  'PingFang SC', 'Microsoft YaHei', sans-serif;
--font-mono: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', Consolas,
  monospace;
```

- 界面文字用 `--font-sans`（系统字体，零加载延迟）
- 代码展示区用 `--font-mono`（按需加载 JetBrains Mono）

### 3.2 字号体系

| 级别 | 大小 | 行高 | 用途 |
|---|---|---|---|
| Display | `42px` | `1.2` | 首页 Hero 标题 |
| H1 | `28px` | `1.3` | 页面主标题 |
| H2 | `22px` | `1.4` | 模块标题 |
| H3 | `18px` | `1.4` | 卡片标题 |
| Body | `14px` | `1.6` | 正文 |
| Caption | `12px` | `1.5` | 辅助文字、标签 |

### 3.3 字重

| 用途 | 字重 |
|---|---|
| 标题 | `600`（Semi-Bold） |
| 正文 | `400`（Regular） |
| 强调 | `500`（Medium） |

---

## 4. 圆角

| 级别 | 值 | 用途 |
|---|---|---|
| `--radius-sm` | `8px` | 小按钮、Tag、Badge |
| `--radius-md` | `12px` | 输入框、下拉框 |
| `--radius-lg` | `16px` | 卡片、对话框 |
| `--radius-xl` | `24px` | Hero 图标、大面板 |
| `--radius-full` | `9999px` | 头像、圆形按钮 |

---

## 5. 间距

遵循 4px 基数，主要使用 8 的倍数：

| Token | 值 | 用途 |
|---|---|---|
| `--space-1` | `4px` | 图标与文字间距 |
| `--space-2` | `8px` | 紧凑元素间距 |
| `--space-3` | `12px` | 组内间距 |
| `--space-4` | `16px` | 卡片内边距 |
| `--space-5` | `20px` | 模块间距 |
| `--space-6` | `24px` | 区块间距 |
| `--space-8` | `32px` | 大区块间距 |
| `--space-10` | `40px` | 页面边距 |
| `--space-16` | `64px` | Hero 区上下留白 |

---

## 6. 毛玻璃效果

核心视觉特征之一，用于 Header、悬浮面板、侧边栏。

```css
--glass-bg: rgba(255, 255, 255, 0.72);
--glass-blur: 16px;
--glass-border: 1px solid rgba(148, 163, 184, 0.08);
```

应用方式：
```css
.glass {
  background: var(--glass-bg);
  backdrop-filter: blur(var(--glass-blur));
  -webkit-backdrop-filter: blur(var(--glass-blur));
  border: var(--glass-border);
}
```

---

## 7. 动效

### 7.1 缓动函数

```css
--ease-out: cubic-bezier(0.16, 1, 0.3, 1);  /* 主要动效：自然弹出 */
--ease-in-out: cubic-bezier(0.65, 0, 0.35, 1); /* 过渡切换 */
```

### 7.2 时长

| 场景 | 时长 |
|---|---|
| Hover 反馈 | `150ms` |
| 展开/折叠 | `250ms` |
| 页面元素入场 | `400ms` |
| 模态框弹出 | `300ms` |

### 7.3 入场动画

卡片/模块从下方轻微滑入 + 淡入：
```css
@keyframes slideUp {
  from { opacity: 0; transform: translateY(12px); }
  to   { opacity: 1; transform: translateY(0); }
}
```

多条卡片依次入场时，每张间隔 `60ms`。

### 7.4 脉冲动画

分析进行中的状态指示：
```css
@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.5; }
}
```

---

## 8. 品牌标识

### 8.1 Logo

圆角方块 + 渐变底色 + 白色 "S" 字母：

```
┌──────────────┐
│              │
│   渐变蓝绿    │
│     S        │  48×48px (Header) / 96×96px (Hero)
│              │
└──────────────┘
```

- 小尺寸（Header）：`32×32px`，圆角 `10px`，"S" 字号 `14px`
- 大尺寸（Hero）：`96×96px`，圆角 `24px`，"S" 字号 `48px`，带品牌阴影

### 8.2 渐变文字

品牌名 "SecAgent" 使用渐变文字效果：
```css
.gradient-text {
  background: var(--accent-gradient);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
}
```

---

## 9. 页面布局框架

### 9.1 整体结构

```
┌─────────────────────────────────────────────┐
│  Header (毛玻璃, sticky)                      │
│  [Logo] SecAgent                [导航链接]     │
├─────────────────────────────────────────────┤
│                                             │
│              Content Area                   │
│          (最大宽度 1200px 居中)                │
│                                             │
├─────────────────────────────────────────────┤
│  Footer (轻量, 版权信息)                       │
└─────────────────────────────────────────────┘
```

### 9.2 Header

- 高度：`56px`
- 毛玻璃背景，sticky 置顶
- 左侧：Logo + "SecAgent" 渐变文字
- 右侧：导航链接（文字色 `--text-secondary`，hover 变 `--accent-start`，无下划线）
- 底部 1px 轻分割线

### 9.3 Content

- 最大宽度 `1200px`，水平居中
- 水平内边距 `24px`（移动端 `16px`）

### 9.4 Footer

- 高度自适应，通常 `48px`
- 背景：`transparent` 或 `rgba(255,255,255,0.5)`
- 顶部 1px 轻分割线
- 文字 `--text-muted`，字号 `13px`，居中

---

## 10. 首页设计（1.7 交付物）

### 10.1 首页结构

```
┌─────────────────────────────────────────────┐
│  Header                                      │
├─────────────────────────────────────────────┤
│                                             │
│              ┌─────────┐                    │
│              │   渐变S   │  96×96 大Logo     │
│              └─────────┘                    │
│                                             │
│            SecAgent                         │
│     （渐变文字，42px Display）                 │
│                                             │
│   基于大语言模型的智能安全分析平台               │
│      （次文字，16px）                          │
│                                             │
│    [ 开始代码扫描 ]  [ 上传恶意分析 ]            │
│      （渐变主按钮）    （白底描边按钮）           │
│                                             │
├─────────────────────────────────────────────┤
│  Footer                                      │
└─────────────────────────────────────────────┘
```

### 10.2 Hero 区细节

- 整体垂直居中，最小高度 `calc(100vh - 56px - 48px)`
- Logo 与标题间距 `32px`
- 标题与副标题间距 `16px`
- 副标题与按钮区间距 `40px`
- 两个按钮间距 `16px`
- 所有元素居中对齐

### 10.3 按钮样式

**主按钮（渐变）**：
- 背景：`var(--accent-gradient)`
- 文字：白色，`14px`，`500` 字重
- 圆角：`12px`
- 内边距：`12px 28px`
- 阴影：品牌阴影
- Hover：亮度微增 + 阴影扩大

**次按钮（描边）**：
- 背景：`#FFFFFF`
- 文字：`--accent-start`，`14px`，`500` 字重
- 边框：`1.5px solid rgba(91,163,255,0.3)`
- 圆角：`12px`
- 内边距：`12px 28px`
- Hover：边框变实色 + 浅蓝底 `rgba(91,163,255,0.06)`

---

## 11. 后续页面风格推演

本设计系统在后续页面的应用原则：

| 页面 | 风格要点 |
|---|---|
| 仪表盘 | 白色卡片网格 + 统计数字用渐变色 + ECharts 使用蓝绿主色 |
| 任务提交 | 左右分栏：左侧输入区（代码编辑器/上传区），右侧预览 |
| 分析过程 | 思维链卡片纵向排列，Thought/Action/Observation 用左侧色条区分（蓝/橙/绿），非背景色 |
| 报告展示 | 白色报告文档风格，风险等级用语义色小标签，表格轻量无粗线 |
| 历史列表 | 标准 Ant Design Table，极简配置，去掉斑马纹，hover 时行高亮 |

---

## 12. Ant Design 主题覆盖

通过 ConfigProvider 统一定制 Ant Design 组件风格：

```tsx
const theme = {
  token: {
    colorPrimary: '#5BA3FF',
    colorBgContainer: '#FFFFFF',
    colorBgLayout: '#FAF9F7',
    borderRadius: 12,
    fontFamily: '-apple-system, BlinkMacSystemFont, Segoe UI, Roboto, PingFang SC, Microsoft YaHei, sans-serif',
    fontSize: 14,
  },
  components: {
    Layout: {
      headerBg: 'rgba(255,255,255,0.72)',
      bodyBg: '#FAF9F7',
      footerBg: 'transparent',
    },
    Button: {
      primaryShadow: '0 8px 32px rgba(91,163,255,0.25)',
      borderRadius: 12,
    },
    Card: {
      borderRadiusLG: 16,
      boxShadowTertiary: '0 1px 3px rgba(0,0,0,0.04)',
    },
  },
};
```

---

## 13. CSS 变量汇总

```css
:root {
  /* Background */
  --bg-page: #FAF9F7;
  --bg-card: #FFFFFF;
  --bg-glass: rgba(255, 255, 255, 0.72);

  /* Accent */
  --accent-start: #5BA3FF;
  --accent-end: #5EEAD4;
  --accent-gradient: linear-gradient(135deg, #5BA3FF 0%, #5EEAD4 100%);

  /* Text */
  --text-primary: #1E293B;
  --text-secondary: #64748B;
  --text-muted: #94A3B8;
  --text-inverse: #FFFFFF;

  /* Border */
  --border-light: rgba(148, 163, 184, 0.08);
  --border-normal: rgba(148, 163, 184, 0.12);
  --border-focus: rgba(91, 163, 255, 0.3);

  /* Radius */
  --radius-sm: 8px;
  --radius-md: 12px;
  --radius-lg: 16px;
  --radius-xl: 24px;
  --radius-full: 9999px;

  /* Shadow */
  --shadow-sm: 0 1px 3px rgba(0,0,0,0.04);
  --shadow-md: 0 4px 16px rgba(0,0,0,0.06);
  --shadow-lg: 0 8px 32px rgba(91,163,255,0.12);
  --shadow-brand: 0 8px 32px rgba(91,163,255,0.25);

  /* Glass */
  --glass-blur: 16px;
  --glass-border: 1px solid rgba(148, 163, 184, 0.08);

  /* Spacing */
  --space-1: 4px;
  --space-2: 8px;
  --space-3: 12px;
  --space-4: 16px;
  --space-5: 20px;
  --space-6: 24px;
  --space-8: 32px;
  --space-10: 40px;
  --space-16: 64px;

  /* Animation */
  --ease-out: cubic-bezier(0.16, 1, 0.3, 1);
  --ease-in-out: cubic-bezier(0.65, 0, 0.35, 1);
}
```

---

> **版本**：v1.0
> **日期**：2026-06-09
> **适用范围**：SecAgent 全项目前端
