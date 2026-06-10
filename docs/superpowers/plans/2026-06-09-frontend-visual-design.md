# SecAgent 前端视觉设计与首页 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 建立完整的 SecAgent 前端设计系统（CSS 变量、Ant Design 主题、通用组件）并实现首页，为后续所有页面奠定视觉基础。

**Architecture:** 采用 CSS 变量定义设计 Token，Ant Design ConfigProvider 覆盖组件主题，自定义组件（Header/Hero/Footer）按职责拆分独立文件。App.tsx 作为组合层。

**Tech Stack:** React 19 + TypeScript + Ant Design 6 + Vite 8

---

## File Structure

| 文件 | 职责 | 操作 |
|---|---|---|
| `frontend/index.html` | 更新页面标题 | 修改 |
| `frontend/src/index.css` | CSS 变量 + 全局样式 + 动画 + 毛玻璃 + 渐变文字 | 创建 |
| `frontend/src/theme.ts` | Ant Design ConfigProvider 主题配置 | 创建 |
| `frontend/src/components/Header.tsx` | 毛玻璃 sticky Header | 创建 |
| `frontend/src/components/Hero.tsx` | 首页居中 Hero 区（Logo + 标题 + 按钮） | 创建 |
| `frontend/src/components/Footer.tsx` | 轻量 Footer | 创建 |
| `frontend/src/App.tsx` | 组合 Header + Hero + Footer | 创建 |
| `frontend/src/main.tsx` | 入口，包裹 ConfigProvider | 修改 |

---

### Task 1: 更新 index.html 页面标题

**Files:**
- Modify: `frontend/index.html`

- [ ] **Step 1: 更新 title 标签**

将 `<title>frontend</title>` 改为 `<title>SecAgent - 智能安全分析平台</title>`。

- [ ] **Step 2: 验证**

运行 `cd frontend && npm run dev`，浏览器标签页应显示 "SecAgent - 智能安全分析平台"。

---

### Task 2: 创建 CSS 设计系统 (index.css)

**Files:**
- Create: `frontend/src/index.css`

- [ ] **Step 1: 写入完整的 CSS 文件**

```css
* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

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
  --shadow-sm: 0 1px 3px rgba(0, 0, 0, 0.04);
  --shadow-md: 0 4px 16px rgba(0, 0, 0, 0.06);
  --shadow-lg: 0 8px 32px rgba(91, 163, 255, 0.12);
  --shadow-brand: 0 8px 32px rgba(91, 163, 255, 0.25);

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

body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto,
    'PingFang SC', 'Microsoft YaHei', sans-serif;
  background-color: var(--bg-page);
  color: var(--text-primary);
  min-height: 100vh;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}

#root {
  min-height: 100vh;
}

/* Gradient text */
.gradient-text {
  background: var(--accent-gradient);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
}

/* Glass effect */
.glass {
  background: var(--bg-glass);
  backdrop-filter: blur(var(--glass-blur));
  -webkit-backdrop-filter: blur(var(--glass-blur));
  border-bottom: var(--glass-border);
}

/* Animations */
@keyframes slideUp {
  from {
    opacity: 0;
    transform: translateY(12px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

@keyframes pulse {
  0%, 100% {
    opacity: 1;
  }
  50% {
    opacity: 0.5;
  }
}

/* Entrance animation helper */
.animate-slide-up {
  animation: slideUp 0.4s var(--ease-out) both;
}
```

---

### Task 3: 创建 Ant Design 主题配置

**Files:**
- Create: `frontend/src/theme.ts`

- [ ] **Step 1: 写入主题配置文件**

```ts
import type { ThemeConfig } from 'antd';

const theme: ThemeConfig = {
  token: {
    colorPrimary: '#5BA3FF',
    colorBgContainer: '#FFFFFF',
    colorBgLayout: '#FAF9F7',
    borderRadius: 12,
    fontFamily:
      "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'PingFang SC', 'Microsoft YaHei', sans-serif",
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

export default theme;
```

---

### Task 4: 创建 Header 组件

**Files:**
- Create: `frontend/src/components/Header.tsx`

- [ ] **Step 1: 写入 Header 组件**

```tsx
import { Layout, Typography } from 'antd';

const { Header: AntHeader } = Layout;

function Header() {
  return (
    <AntHeader
      className="glass"
      style={{
        position: 'sticky',
        top: 0,
        zIndex: 100,
        height: 56,
        padding: '0 24px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <div
          style={{
            width: 32,
            height: 32,
            borderRadius: 10,
            background: 'var(--accent-gradient)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
          }}
        >
          <span style={{ color: 'white', fontWeight: 700, fontSize: 14 }}>S</span>
        </div>
        <Typography.Text
          className="gradient-text"
          style={{ fontSize: 16, fontWeight: 600 }}
        >
          SecAgent
        </Typography.Text>
      </div>
    </AntHeader>
  );
}

export default Header;
```

---

### Task 5: 创建 Hero 组件

**Files:**
- Create: `frontend/src/components/Hero.tsx`

- [ ] **Step 1: 写入 Hero 组件**

```tsx
import { Button, Typography } from 'antd';
import { CodeOutlined, SecurityScanOutlined } from '@ant-design/icons';

function Hero() {
  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        minHeight: 'calc(100vh - 56px - 48px)',
        padding: '0 24px',
      }}
    >
      <div className="animate-slide-up">
        {/* Logo */}
        <div
          style={{
            width: 96,
            height: 96,
            borderRadius: 24,
            background: 'var(--accent-gradient)',
            boxShadow: 'var(--shadow-brand)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            margin: '0 auto 32px',
          }}
        >
          <span style={{ color: 'white', fontWeight: 700, fontSize: 48 }}>S</span>
        </div>
      </div>

      <div className="animate-slide-up" style={{ animationDelay: '60ms' }}>
        <Typography.Title
          level={1}
          className="gradient-text"
          style={{ fontSize: 42, fontWeight: 700, textAlign: 'center', marginBottom: 16 }}
        >
          SecAgent
        </Typography.Title>
      </div>

      <div className="animate-slide-up" style={{ animationDelay: '120ms' }}>
        <Typography.Paragraph
          style={{
            fontSize: 16,
            color: 'var(--text-secondary)',
            textAlign: 'center',
            maxWidth: 400,
            marginBottom: 40,
          }}
        >
          基于大语言模型的智能安全分析平台
        </Typography.Paragraph>
      </div>

      <div
        className="animate-slide-up"
        style={{ animationDelay: '180ms', display: 'flex', gap: 16 }}
      >
        <Button
          type="primary"
          size="large"
          icon={<CodeOutlined />}
          style={{
            background: 'var(--accent-gradient)',
            border: 'none',
            borderRadius: 12,
            padding: '12px 28px',
            height: 'auto',
            boxShadow: 'var(--shadow-brand)',
          }}
        >
          开始代码扫描
        </Button>
        <Button
          size="large"
          icon={<SecurityScanOutlined />}
          style={{
            borderRadius: 12,
            padding: '12px 28px',
            height: 'auto',
            borderColor: 'var(--border-focus)',
            color: 'var(--accent-start)',
          }}
        >
          上传恶意分析
        </Button>
      </div>
    </div>
  );
}

export default Hero;
```

---

### Task 6: 创建 Footer 组件

**Files:**
- Create: `frontend/src/components/Footer.tsx`

- [ ] **Step 1: 写入 Footer 组件**

```tsx
import { Layout, Typography } from 'antd';

const { Footer: AntFooter } = Layout;

function Footer() {
  return (
    <AntFooter
      style={{
        background: 'transparent',
        borderTop: '1px solid var(--border-light)',
        padding: 16,
        textAlign: 'center',
      }}
    >
      <Typography.Text style={{ color: 'var(--text-muted)', fontSize: 13 }}>
        SecAgent - 智能安全分析平台 ©2026
      </Typography.Text>
    </AntFooter>
  );
}

export default Footer;
```

---

### Task 7: 创建 App.tsx

**Files:**
- Create: `frontend/src/App.tsx`

- [ ] **Step 1: 写入 App 组件**

```tsx
import { Layout } from 'antd';
import Header from './components/Header';
import Hero from './components/Hero';
import Footer from './components/Footer';

const { Content } = Layout;

function App() {
  return (
    <Layout style={{ minHeight: '100vh', background: 'var(--bg-page)' }}>
      <Header />
      <Content>
        <Hero />
      </Content>
      <Footer />
    </Layout>
  );
}

export default App;
```

---

### Task 8: 更新 main.tsx 接入主题

**Files:**
- Modify: `frontend/src/main.tsx`

- [ ] **Step 1: 用 ConfigProvider 包裹 App**

```tsx
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { ConfigProvider } from 'antd';
import zhCN from 'antd/locale/zh_CN';
import theme from './theme';
import './index.css';
import App from './App';

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <ConfigProvider theme={theme} locale={zhCN}>
      <App />
    </ConfigProvider>
  </StrictMode>,
);
```

- [ ] **Step 2: 验证构建无报错**

运行: `cd frontend && npx tsc --noEmit`
预期: 无 TypeScript 错误

---

### Task 9: 启动验证

- [ ] **Step 1: 启动开发服务器**

运行: `cd frontend && npm run dev`

- [ ] **Step 2: 视觉验证清单**

在浏览器中逐项确认：
- [ ] 页面背景为奶白色（`#FAF9F7`），不是纯白
- [ ] Header 毛玻璃效果（半透明白底 + 模糊），sticky 置顶
- [ ] Header 左侧有蓝色渐变小 Logo（32px 圆角方块 + 白色 "S"）+ 渐变 "SecAgent" 文字
- [ ] Hero 区垂直居中，96px 大 Logo 带品牌阴影
- [ ] "SecAgent" 标题为蓝绿渐变文字，42px
- [ ] 副标题灰色，"基于大语言模型的智能安全分析平台"
- [ ] 两个按钮：渐变主按钮 "开始代码扫描" + 描边次按钮 "上传恶意分析"
- [ ] 各元素依次滑入（slideUp 动画，60ms 间隔）
- [ ] Footer 底部居中显示版权文字
- [ ] 整体感觉：轻量、通透、年轻，不像传统安全产品

- [ ] **Step 3: Commit**

```bash
git add frontend/index.html frontend/src/index.css frontend/src/theme.ts frontend/src/components/ frontend/src/App.tsx frontend/src/main.tsx
git commit -m "feat: establish frontend design system and homepage (1.7)"
```
