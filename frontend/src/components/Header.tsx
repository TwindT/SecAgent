import { useState, useEffect } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { Menu, Switch } from 'antd'
import type { MenuProps } from 'antd'
import {
  Home,
  LayoutDashboard,
  Upload,
  Shield,
  FileText,
  History,
  Sun,
  Moon,
} from 'lucide-react'
import Logo from './Logo'

// ─── Navigation items mapping ────────────────────────
const navItems = [
  { key: '/', label: '首页', icon: Home },
  { key: '/dashboard', label: '仪表盘', icon: LayoutDashboard },
  { key: '/submit', label: '任务提交', icon: Upload },
  { key: '/analysis', label: '分析过程', icon: Shield },
  { key: '/report', label: '分析报告', icon: FileText },
  { key: '/history', label: '历史记录', icon: History },
]

// ─── Ant Design Menu items ───────────────────────────
const menuItems: MenuProps['items'] = navItems.map((item) => ({
  key: item.key,
  icon: <item.icon size={16} />,
  label: item.label,
}))

function Header() {
  const location = useLocation()
  const navigate = useNavigate()
  const [isDark, setIsDark] = useState(() => {
    return localStorage.getItem('theme') === 'dark'
  })

  // Apply theme on mount and when isDark changes
  useEffect(() => {
    if (isDark) {
      document.documentElement.setAttribute('data-theme', 'dark')
    } else {
      document.documentElement.removeAttribute('data-theme')
    }
    localStorage.setItem('theme', isDark ? 'dark' : 'light')
  }, [isDark])

  // Determine active key from current path
  const getSelectedKey = () => {
    const path = location.pathname
    // Match exact or prefix for dynamic routes
    if (path === '/') return '/'
    if (path.startsWith('/dashboard')) return '/dashboard'
    if (path.startsWith('/submit')) return '/submit'
    if (path.startsWith('/analysis')) return '/analysis'
    if (path.startsWith('/report')) return '/report'
    if (path.startsWith('/history')) return '/history'
    return '/'
  }

  const handleMenuClick: MenuProps['onClick'] = ({ key }) => {
    navigate(key)
  }

  const handleThemeToggle = (checked: boolean) => {
    setIsDark(checked)
  }

  return (
    <header
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
        borderBottom: '1px solid var(--border-light)',
      }}
    >
      {/* Logo & Brand */}
      <div
        style={{ display: 'flex', alignItems: 'center', gap: 10, cursor: 'pointer' }}
        onClick={() => navigate('/')}
      >
        <Logo size={32} />
        <span
          className="gradient-text"
          style={{ fontSize: 18, fontWeight: 600 }}
        >
          SecAgent
        </span>
      </div>

      {/* Navigation Menu */}
      <Menu
        mode="horizontal"
        selectedKeys={[getSelectedKey()]}
        items={menuItems}
        onClick={handleMenuClick}
        style={{
          flex: 1,
          justifyContent: 'center',
          border: 'none',
          background: 'transparent',
          fontWeight: 500,
          fontSize: 14,
          minWidth: 0,
        }}
        // Override Ant Design default styles to match our design system
        // These are applied via inline style overrides
      />

      {/* Right: Theme Toggle */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <Sun size={16} style={{ color: isDark ? 'var(--text-muted)' : 'var(--accent-start)' }} />
        <Switch
          size="small"
          checked={isDark}
          onChange={handleThemeToggle}
          style={{ background: isDark ? 'var(--accent-start)' : undefined }}
        />
        <Moon size={16} style={{ color: isDark ? 'var(--accent-start)' : 'var(--text-muted)' }} />
      </div>
    </header>
  )
}

export default Header
