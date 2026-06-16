import {
  ShieldCheck,
  FileSearch,
  AlertTriangle,
  Clock,
  Code2,
  Bug,
  ChevronRight,
  Activity,
  TrendingUp,
  CheckCircle2,
  Loader2,
  Zap,
  BarChart3,
} from 'lucide-react'
import { Tag } from 'antd'
import {
  VulnTypeDonutChart,
  TaskTrendChart,
  RiskRadarChart,
  SeverityBarChart,
  TaskSuccessRateChart,
  DurationDistChart,
} from '@/components/secagent/VisualizationCharts'
import { useState, useEffect, useCallback, useRef } from 'react'
import { Skeleton } from 'antd'
import { fetchStats, type StatsResponse } from '@/services/api'
import { useNavigate } from 'react-router-dom'

// ─── Status helpers ─────────────────────────────────
function getStatusTag(status: string) {
  switch (status) {
    case 'done':
      return (
        <Tag
          style={{
            fontSize: '12px',
            fontWeight: 500,
            background: 'rgba(16,185,129,0.1)',
            color: '#10B981',
            border: 'none',
            borderRadius: '6px',
            padding: '0 8px',
            lineHeight: '22px',
          }}
        >
          分析完成
        </Tag>
      )
    case 'analyzing':
      return (
        <Tag
          className="animate-pulse-soft"
          style={{
            fontSize: '12px',
            fontWeight: 500,
            background: 'rgba(91,163,255,0.1)',
            color: '#5BA3FF',
            border: 'none',
            borderRadius: '6px',
            padding: '0 8px',
            lineHeight: '22px',
          }}
        >
          分析中
        </Tag>
      )
    case 'failed':
      return (
        <Tag
          style={{
            fontSize: '12px',
            fontWeight: 500,
            background: 'rgba(239,68,68,0.1)',
            color: '#EF4444',
            border: 'none',
            borderRadius: '6px',
            padding: '0 8px',
            lineHeight: '22px',
          }}
        >
          失败
        </Tag>
      )
    case 'pending':
      return (
        <Tag
          style={{
            fontSize: '12px',
            fontWeight: 500,
            background: 'rgba(148,163,184,0.1)',
            color: '#94A3B8',
            border: 'none',
            borderRadius: '6px',
            padding: '0 8px',
            lineHeight: '22px',
          }}
        >
          等待中
        </Tag>
      )
    default:
      return null
  }
}

function getSeverityDot(severity: string | null) {
  if (!severity) return null
  const colors: Record<string, string> = {
    high: '#EF4444',
    medium: '#F59E0B',
    low: '#10B981',
  }
  return (
    <span
      style={{
        display: 'inline-block',
        borderRadius: '50%',
        width: '8px',
        height: '8px',
        background: colors[severity] || '#94A3B8',
      }}
    />
  )
}

// ─── Mini Sparkline Component ──────────────────────
function MiniSparkline({ data, color }: { data: number[]; color: string }) {
  if (data.length < 2) return null
  const max = Math.max(...data)
  const min = Math.min(...data)
  const range = max - min || 1
  const width = 80
  const height = 28
  const points = data
    .map((v, i) => {
      const x = (i / (data.length - 1)) * width
      const y = height - 2 - ((v - min) / range) * (height - 4)
      return `${x},${y}`
    })
    .join(' ')

  return (
    <svg width={width} height={height} style={{ flexShrink: 0 }}>
      <polyline
        points={points}
        fill="none"
        stroke={color}
        strokeWidth={1.5}
        strokeLinecap="round"
        strokeLinejoin="round"
        opacity={0.6}
      />
    </svg>
  )
}

// ─── Animated Number Component ─────────────────────
function AnimatedNumber({ value, duration = 800 }: { value: number; duration?: number }) {
  const [display, setDisplay] = useState(0)
  const prevValue = useRef(0)

  useEffect(() => {
    const start = prevValue.current
    const end = value
    const startTime = Date.now()

    const animate = () => {
      const elapsed = Date.now() - startTime
      const progress = Math.min(elapsed / duration, 1)
      // ease-out cubic
      const eased = 1 - Math.pow(1 - progress, 3)
      setDisplay(Math.round(start + (end - start) * eased))
      if (progress < 1) {
        requestAnimationFrame(animate)
      }
    }
    requestAnimationFrame(animate)
    prevValue.current = value

    return () => {}
  }, [value, duration])

  return <>{display}</>
}

// ─── Elapsed Time Counter ──────────────────────────
function ElapsedTimeCounter({ startTime }: { startTime: string }) {
  const [elapsed, setElapsed] = useState('0s')

  useEffect(() => {
    const start = new Date(startTime).getTime()
    const update = () => {
      const now = Date.now()
      const diff = Math.max(0, now - start)
      const seconds = Math.floor(diff / 1000)
      if (seconds < 60) {
        setElapsed(`${seconds}s`)
      } else {
        const mins = Math.floor(seconds / 60)
        const secs = seconds % 60
        setElapsed(`${mins}m ${secs}s`)
      }
    }
    update()
    const interval = setInterval(update, 1000)
    return () => clearInterval(interval)
  }, [startTime])

  return <>{elapsed}</>
}

// ─── Mock 数据（前后端联调前用于展示效果） ──────────
const MOCK_STATS: StatsResponse = {
  total_tasks: 42,
  today_tasks: 8,
  high_severity_tasks: 5,
  avg_duration: '2m 35s',
  recent_tasks: [
    {
      id: 1,
      type: 'vulnerability_detection',
      status: 'done',
      input_path: 'auth_module.py',
      input_content: undefined,
      result_json: '{"severity":"high","vuln_count":3}',
      created_at: new Date(Date.now() - 15 * 60 * 1000).toISOString(),
      updated_at: new Date(Date.now() - 12 * 60 * 1000).toISOString(),
      analysis_steps: [],
    },
    {
      id: 2,
      type: 'malware_analysis',
      status: 'done',
      input_path: 'suspicious_payload.exe',
      input_content: undefined,
      result_json: '{"severity":"high","vuln_count":7}',
      created_at: new Date(Date.now() - 45 * 60 * 1000).toISOString(),
      updated_at: new Date(Date.now() - 42 * 60 * 1000).toISOString(),
      analysis_steps: [],
    },
    {
      id: 3,
      type: 'vulnerability_detection',
      status: 'analyzing',
      input_path: 'payment_api.py',
      input_content: undefined,
      result_json: undefined,
      created_at: new Date(Date.now() - 3 * 60 * 1000).toISOString(),
      updated_at: new Date(Date.now() - 3 * 60 * 1000).toISOString(),
      analysis_steps: [],
    },
    {
      id: 4,
      type: 'malware_analysis',
      status: 'done',
      input_path: 'macro_doc.xlsx',
      input_content: undefined,
      result_json: '{"severity":"medium","vuln_count":2}',
      created_at: new Date(Date.now() - 90 * 60 * 1000).toISOString(),
      updated_at: new Date(Date.now() - 87 * 60 * 1000).toISOString(),
      analysis_steps: [],
    },
    {
      id: 5,
      type: 'vulnerability_detection',
      status: 'failed',
      input_path: 'dashboard.js',
      input_content: undefined,
      result_json: undefined,
      created_at: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
      updated_at: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
      analysis_steps: [],
    },
  ],
  tasks_by_type: [
    { type: 'vulnerability_detection', count: 28 },
    { type: 'malware_analysis', count: 14 },
  ],
  tasks_by_severity: [
    { severity: 'high', count: 5 },
    { severity: 'medium', count: 12 },
    { severity: 'low', count: 18 },
    { severity: 'info', count: 7 },
  ],
  tasks_by_day: [
    { date: '06-09', count: 4 },
    { date: '06-10', count: 7 },
    { date: '06-11', count: 5 },
    { date: '06-12', count: 9 },
    { date: '06-13', count: 6 },
    { date: '06-14', count: 3 },
    { date: '06-15', count: 8 },
  ],
}

// ─── Component ──────────────────────────────────────
const Dashboard = () => {
  const navigate = useNavigate()
  const [isLoading, setIsLoading] = useState(true)
  const [stats, setStats] = useState<StatsResponse | null>(null)
  const [progressAnimated, setProgressAnimated] = useState(false)
  const [analyzingProgress, setAnalyzingProgress] = useState<Record<string, number>>({})

  // Fetch real data from API, fallback to mock data
  useEffect(() => {
    fetchStats()
      .then((res) => setStats(res.data))
      .catch(() => {
        // 后端未就绪时使用 mock 数据展示效果
        console.warn('[Dashboard] API 不可用，使用 mock 数据展示')
        setStats(MOCK_STATS)
      })
      .finally(() => setIsLoading(false))
  }, [])

  // Auto-refresh stats every 30s for live data
  useEffect(() => {
    const interval = setInterval(() => {
      fetchStats()
        .then((res) => setStats(res.data))
        .catch(() => {})
    }, 30000)
    return () => clearInterval(interval)
  }, [])

  // Animate progress bars after data loads
  useEffect(() => {
    if (!isLoading && stats) {
      const timer = setTimeout(() => setProgressAnimated(true), 100)
      return () => clearTimeout(timer)
    }
  }, [isLoading, stats])

  // Simulate progress for analyzing tasks
  useEffect(() => {
    const analyzingTasks = (stats?.recent_tasks ?? []).filter(t => t.status === 'analyzing')
    if (analyzingTasks.length === 0) return

    const interval = setInterval(() => {
      setAnalyzingProgress(prev => {
        const next = { ...prev }
        analyzingTasks.forEach(task => {
          const current = next[task.id] ?? 10
          // Slowly increment progress, max out at 92%
          if (current < 92) {
            next[task.id] = current + Math.random() * 2
          }
        })
        return next
      })
    }, 2000)

    return () => clearInterval(interval)
  }, [stats?.recent_tasks])

  // Compute status counts for success rate chart
  const getStatusCounts = useCallback(() => {
    const tasks = stats?.recent_tasks ?? []
    return {
      done: tasks.filter(t => t.status === 'done').length,
      failed: tasks.filter(t => t.status === 'failed').length,
      analyzing: tasks.filter(t => t.status === 'analyzing').length,
      pending: tasks.filter(t => t.status === 'pending').length,
    }
  }, [stats?.recent_tasks])

  // Sparkline data generation from tasks_by_day
  const sparklineData = (stats?.tasks_by_day ?? []).map(d => d.count)

  if (isLoading) {
    return (
      <div style={{ maxWidth: '1200px', margin: '0 auto', width: '100%', padding: '24px 16px' }}>
        <div style={{ marginBottom: '24px' }}>
          <Skeleton.Input active style={{ width: 200, height: 28 }} />
          <Skeleton.Input active style={{ width: 280, height: 14, marginTop: 8 }} />
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px', marginBottom: '24px' }}>
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton.Input key={i} active style={{ height: 120, borderRadius: 16 }} />
          ))}
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '24px' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <Skeleton.Input active style={{ height: 200, borderRadius: 16 }} />
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <Skeleton.Input active style={{ height: 150, borderRadius: 16 }} />
            <Skeleton.Input active style={{ height: 150, borderRadius: 16 }} />
          </div>
        </div>
      </div>
    )
  }

  return (
    <div style={{ maxWidth: '1200px', margin: '0 auto', width: '100%', padding: '24px 16px' }}>
      {/* Page Title */}
      <div className="animate-slide-up" style={{ marginBottom: '24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div>
            <h1
              style={{
                fontWeight: 600,
                fontSize: '28px',
                lineHeight: '1.3',
                color: 'var(--text-primary)',
              }}
            >
              安全分析仪表盘
            </h1>
            <p
              style={{
                marginTop: '4px',
                fontSize: '14px',
                color: 'var(--text-secondary)',
              }}
            >
              实时监控安全分析任务状态与发现
            </p>
          </div>
          <button
            onClick={() => {
              setIsLoading(true)
              setProgressAnimated(false)
              fetchStats()
                .then((res) => setStats(res.data))
                .catch(() => {
                  console.warn('[Dashboard] API 不可用，使用 mock 数据展示')
                  setStats(MOCK_STATS)
                })
                .finally(() => setIsLoading(false))
            }}
            className="btn-press focus-ring"
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              borderRadius: '12px',
              border: '1px solid var(--border-light)',
              padding: '10px 16px',
              fontSize: '12px',
              fontWeight: 500,
              color: 'var(--text-secondary)',
              background: 'var(--bg-card)',
              transition: 'all 0.15s',
              cursor: 'pointer',
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.borderColor = 'var(--border-focus)'
              e.currentTarget.style.color = 'var(--accent-start)'
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.borderColor = 'var(--border-light)'
              e.currentTarget.style.color = 'var(--text-secondary)'
            }}
          >
            <Zap size={14} />
            刷新数据
          </button>
        </div>
      </div>

      {/* Stats Cards with Sparklines */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px', marginBottom: '24px' }}>
        {[
          {
            title: '今日任务',
            value: stats?.today_tasks ?? 0,
            isNumeric: true,
            change: `较昨日 +${Math.min(stats?.today_tasks ?? 0, 3)}`,
            changeUp: true,
            icon: Activity,
            color: '#5BA3FF',
            bgColor: 'rgba(91,163,255,0.08)',
            sparkColor: '#5BA3FF',
          },
          {
            title: '总任务数',
            value: stats?.total_tasks ?? 0,
            isNumeric: true,
            change: `${stats?.total_tasks ?? 0} 个任务`,
            changeUp: true,
            icon: FileSearch,
            color: '#5EEAD4',
            bgColor: 'rgba(94,234,212,0.08)',
            sparkColor: '#5EEAD4',
          },
          {
            title: '高危发现',
            value: stats?.high_severity_tasks ?? 0,
            isNumeric: true,
            change: (stats?.high_severity_tasks ?? 0) > 0 ? `需关注` : `安全`,
            changeUp: (stats?.high_severity_tasks ?? 0) === 0,
            icon: AlertTriangle,
            color: '#EF4444',
            bgColor: 'rgba(239,68,68,0.08)',
            sparkColor: '#EF4444',
          },
          {
            title: '平均耗时',
            value: 0,
            isNumeric: false,
            displayValue: stats?.avg_duration ?? '0s',
            change: `分析效率`,
            changeUp: true,
            icon: Clock,
            color: '#F59E0B',
            bgColor: 'rgba(245,158,11,0.08)',
            sparkColor: '#F59E0B',
          },
        ].map((stat, index) => {
          const Icon = stat.icon
          return (
            <div
              key={stat.title}
              className="animate-slide-up card-hover stat-card-gradient"
              style={{
                borderRadius: '16px',
                border: '1px solid var(--border-light)',
                padding: '20px',
                boxShadow: 'var(--shadow-sm)',
                animationDelay: `${index * 60}ms`,
                animationFillMode: 'both',
                background: 'var(--bg-card)',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    borderRadius: '12px',
                    width: '40px',
                    height: '40px',
                    background: stat.bgColor,
                  }}
                >
                  <Icon size={20} style={{ color: stat.color }} />
                </div>
                <MiniSparkline data={sparklineData.length > 1 ? sparklineData : []} color={stat.sparkColor} />
              </div>
              <div style={{ marginTop: '16px' }}>
                <div
                  className="number-count-up"
                  style={{
                    fontSize: '24px',
                    fontWeight: 600,
                    color: 'var(--text-primary)',
                    animationDelay: `${index * 60 + 200}ms`,
                  }}
                >
                  {stat.isNumeric ? <AnimatedNumber value={stat.value} /> : stat.displayValue}
                </div>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: '6px' }}>
                  <span
                    style={{ fontSize: '12px', fontWeight: 500, color: 'var(--text-secondary)' }}
                  >
                    {stat.title}
                  </span>
                  <span
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '4px',
                      fontSize: '11px',
                      fontWeight: 600,
                      color: stat.changeUp ? '#10B981' : '#EF4444',
                    }}
                  >
                    {stat.changeUp && <TrendingUp size={10} />}
                    {stat.change}
                  </span>
                </div>
              </div>
            </div>
          )
        })}
      </div>

      {/* Quick Action Buttons */}
      <div className="animate-slide-up" style={{ marginBottom: '24px', animationDelay: '240ms', animationFillMode: 'both' }}>
        <h2
          style={{
            marginBottom: '16px',
            fontWeight: 600,
            fontSize: '18px',
            color: 'var(--text-primary)',
          }}
        >
          快捷操作
        </h2>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '16px' }}>
          {/* Code Scan Button */}
          <button
            onClick={() => navigate('/submit?tab=code')}
            className="btn-press quick-action-btn focus-ring"
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '16px',
              borderRadius: '16px',
              border: '1px solid var(--border-light)',
              background: 'var(--bg-card)',
              padding: '24px',
              textAlign: 'left',
              transition: 'all 0.15s',
              cursor: 'pointer',
              boxShadow: 'var(--shadow-sm)',
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.borderColor = 'var(--border-focus)'
              e.currentTarget.style.transform = 'translateY(-2px)'
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.borderColor = 'var(--border-light)'
              e.currentTarget.style.transform = 'translateY(0)'
            }}
          >
            <div
              className="gradient-bg"
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                borderRadius: '16px',
                width: '48px',
                height: '48px',
                boxShadow: 'var(--shadow-brand)',
                flexShrink: 0,
              }}
            >
              <Code2 size={22} style={{ color: 'white' }} />
            </div>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div
                style={{ fontWeight: 600, fontSize: '16px', color: 'var(--text-primary)' }}
              >
                代码漏洞扫描
              </div>
              <div
                style={{ marginTop: '4px', fontSize: '13px', color: 'var(--text-secondary)' }}
              >
                粘贴或上传源代码，AI 自动检测安全漏洞
              </div>
            </div>
            <ChevronRight
              size={20}
              style={{ color: 'var(--text-muted)' }}
            />
          </button>

          {/* Malware Analysis Button */}
          <button
            onClick={() => navigate('/submit?tab=malware')}
            className="btn-press quick-action-btn focus-ring"
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '16px',
              borderRadius: '16px',
              border: '1px solid var(--border-light)',
              background: 'var(--bg-card)',
              padding: '24px',
              textAlign: 'left',
              transition: 'all 0.15s',
              cursor: 'pointer',
              boxShadow: 'var(--shadow-sm)',
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.borderColor = 'rgba(94,234,212,0.3)'
              e.currentTarget.style.transform = 'translateY(-2px)'
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.borderColor = 'var(--border-light)'
              e.currentTarget.style.transform = 'translateY(0)'
            }}
          >
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                borderRadius: '16px',
                width: '48px',
                height: '48px',
                background: 'linear-gradient(135deg, #5EEAD4 0%, #10B981 100%)',
                boxShadow: '0 8px 32px rgba(94,234,212,0.25)',
                flexShrink: 0,
              }}
            >
              <Bug size={22} style={{ color: 'white' }} />
            </div>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div
                style={{ fontWeight: 600, fontSize: '16px', color: 'var(--text-primary)' }}
              >
                恶意代码分析
              </div>
              <div
                style={{ marginTop: '4px', fontSize: '13px', color: 'var(--text-secondary)' }}
              >
                上传可疑文件，AI 智能判定恶意性并提取指标
              </div>
            </div>
            <ChevronRight
              size={20}
              style={{ color: 'var(--text-muted)' }}
            />
          </button>
        </div>
      </div>

      {/* Active Analysis Progress (Enhanced) */}
      {(stats?.recent_tasks ?? []).filter(t => t.status === 'analyzing').length > 0 && (
        <div
          className="animate-slide-up"
          style={{ marginBottom: '24px', animationDelay: '300ms', animationFillMode: 'both' }}
        >
          <div
            style={{
              borderRadius: '16px',
              border: '1px solid rgba(91,163,255,0.2)',
              overflow: 'hidden',
              boxShadow: '0 4px 24px rgba(91,163,255,0.08)',
            }}
          >
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '12px',
                borderBottom: '1px solid rgba(91,163,255,0.1)',
                padding: '12px 24px',
                background: 'rgba(91,163,255,0.03)',
              }}
            >
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  borderRadius: '8px',
                  width: '28px',
                  height: '28px',
                  background: 'rgba(91,163,255,0.1)',
                }}
              >
                <Activity size={14} style={{ color: '#5BA3FF' }} />
              </div>
              <h3
                style={{ fontWeight: 600, fontSize: '14px', color: 'var(--accent-start)' }}
              >
                实时分析进度
              </h3>
              <span
                style={{
                  fontSize: '12px',
                  fontWeight: 500,
                  borderRadius: '9999px',
                  padding: '2px 8px',
                  background: 'rgba(91,163,255,0.1)',
                  color: '#5BA3FF',
                }}
              >
                {(stats?.recent_tasks ?? []).filter(t => t.status === 'analyzing').length} 个任务进行中
              </span>
            </div>
            <div>
              {(stats?.recent_tasks ?? []).filter(t => t.status === 'analyzing').map((task) => {
                const progress = analyzingProgress[task.id] ?? 15
                return (
                  <div
                    key={task.id}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '16px',
                      padding: '12px 24px',
                      cursor: 'pointer',
                      transition: 'background 0.15s',
                      borderBottom: '1px solid var(--border-light)',
                    }}
                    onClick={() => navigate(`/analysis/${task.id}`)}
                    onMouseEnter={(e) => {
                      e.currentTarget.style.background = 'rgba(91,163,255,0.02)'
                    }}
                    onMouseLeave={(e) => {
                      e.currentTarget.style.background = 'transparent'
                    }}
                  >
                    <div
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        borderRadius: '12px',
                        width: '32px',
                        height: '32px',
                        background: task.type === 'vulnerability_detection'
                          ? 'rgba(91,163,255,0.1)'
                          : 'rgba(94,234,212,0.1)',
                        flexShrink: 0,
                      }}
                    >
                      {task.type === 'vulnerability_detection'
                        ? <Code2 size={15} style={{ color: '#5BA3FF' }} />
                        : <Bug size={15} style={{ color: '#5EEAD4' }} />
                      }
                    </div>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontSize: '14px', fontWeight: 500, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {task.input_path ? task.input_path.split('/').pop() : task.input_content ? `代码片段 #${task.id}` : `任务 #${task.id}`}
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '4px' }}>
                        <div style={{ flex: 1, height: '6px', borderRadius: '9999px', overflow: 'hidden', background: 'rgba(148,163,184,0.08)' }}>
                          <div
                            className="progress-bar-fill"
                            style={{
                              height: '100%',
                              borderRadius: '9999px',
                              width: `${progress}%`,
                              background: 'var(--accent-gradient)',
                            }}
                          />
                        </div>
                        <span style={{ fontSize: '11px', fontWeight: 500, color: '#5BA3FF' }}>
                          {Math.round(progress)}%
                        </span>
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '4px' }}>
                        <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>
                          已用时 <ElapsedTimeCounter startTime={task.created_at} />
                        </span>
                      </div>
                    </div>
                    <ChevronRight size={16} style={{ color: 'var(--text-muted)' }} />
                  </div>
                )
              })}
            </div>
          </div>
        </div>
      )}

      {/* Main Content Area: Recent Tasks + Distribution */}
      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '24px' }}>
        {/* Recent Tasks List + Trend Chart */}
        <div
          className="animate-slide-up"
          style={{ display: 'flex', flexDirection: 'column', gap: '24px', animationDelay: '300ms', animationFillMode: 'both' }}
        >
          <div
            style={{
              borderRadius: '16px',
              border: '1px solid var(--border-light)',
              background: 'var(--bg-card)',
              boxShadow: 'var(--shadow-sm)',
            }}
          >
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                borderBottom: '1px solid var(--border-light)',
                padding: '16px 24px',
              }}
            >
              <h3
                style={{ fontWeight: 600, fontSize: '16px', color: 'var(--text-primary)' }}
              >
                最近分析
              </h3>
              <button
                onClick={() => navigate('/history')}
                style={{
                  fontSize: '12px',
                  fontWeight: 500,
                  color: 'var(--accent-start)',
                  background: 'none',
                  border: 'none',
                  cursor: 'pointer',
                  transition: 'color 0.15s',
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.color = 'var(--accent-end)'
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.color = 'var(--accent-start)'
                }}
              >
                查看全部 →
              </button>
            </div>
            <div>
              {(stats?.recent_tasks ?? []).map((task) => (
                <div
                  key={task.id}
                  className="recent-item-hover card-hover"
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '16px',
                    padding: '16px 24px',
                    cursor: 'pointer',
                    borderBottom: '1px solid var(--border-light)',
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.background = 'rgba(91,163,255,0.02)'
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.background = 'transparent'
                  }}
                  onClick={() => {
                    if (task.status === 'done') {
                      navigate(`/report/${task.id}`)
                    } else if (task.status === 'analyzing') {
                      navigate(`/analysis/${task.id}`)
                    } else if (task.status === 'failed') {
                      navigate(`/analysis/${task.id}`)
                    } else if (task.status === 'pending') {
                      navigate(`/analysis/${task.id}`)
                    }
                  }}
                >
                  {/* Type Icon */}
                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      borderRadius: '12px',
                      width: '36px',
                      height: '36px',
                      background:
                        task.type === 'vulnerability_detection'
                          ? 'rgba(91,163,255,0.08)'
                          : 'rgba(94,234,212,0.08)',
                      flexShrink: 0,
                    }}
                  >
                    {task.type === 'vulnerability_detection' ? (
                      <Code2
                        size={18}
                        style={{ color: '#5BA3FF' }}
                      />
                    ) : (
                      <Bug
                        size={18}
                        style={{ color: '#5EEAD4' }}
                      />
                    )}
                  </div>

                  {/* Task Info */}
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div
                      style={{
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap',
                        fontWeight: 500,
                        fontSize: '14px',
                        color: 'var(--text-primary)',
                      }}
                    >
                      {task.input_path ? task.input_path.split('/').pop() : task.input_content ? `代码片段 #${task.id}` : `任务 #${task.id}`}
                    </div>
                    <div
                      style={{
                        marginTop: '2px',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '8px',
                        fontSize: '12px',
                        color: 'var(--text-muted)',
                      }}
                    >
                      <span>
                        {task.type === 'vulnerability_detection' ? '代码扫描' : '恶意分析'}
                      </span>
                      <span>·</span>
                      <span>{new Date(task.created_at).toLocaleString('zh-CN', { hour: '2-digit', minute: '2-digit' })}</span>
                    </div>
                  </div>

                  {/* Severity + Status */}
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                    {getSeverityDot(task.result_json ? (() => { try { return JSON.parse(task.result_json).severity } catch { return null } })() : null)}
                    {getStatusTag(task.status)}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Task Trend Chart */}
          <TaskTrendChart data={stats?.tasks_by_day ?? []} />
        </div>

        {/* Right Sidebar: Distribution Charts */}
        <div
          className="animate-slide-up"
          style={{ animationDelay: '360ms', animationFillMode: 'both' }}
        >
          {/* Type Distribution */}
          <div
            style={{
              marginBottom: '24px',
              borderRadius: '16px',
              border: '1px solid var(--border-light)',
              background: 'var(--bg-card)',
              padding: '24px',
              boxShadow: 'var(--shadow-sm)',
            }}
          >
            <h3
              style={{ marginBottom: '16px', fontWeight: 600, fontSize: '16px', color: 'var(--text-primary)' }}
            >
              任务类型分布
            </h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              {(() => {
                const typeMap: Record<string, { label: string; color: string }> = {
                  vulnerability_detection: { label: '代码扫描', color: '#5BA3FF' },
                  malware_analysis: { label: '恶意分析', color: '#5EEAD4' },
                }
                const items = (stats?.tasks_by_type ?? []).map((t) => ({
                  label: typeMap[t.type]?.label ?? t.type,
                  color: typeMap[t.type]?.color ?? '#94A3B8',
                  count: t.count,
                }))
                const total = items.reduce((sum, i) => sum + i.count, 0)
                if (items.length === 0) {
                  return <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>暂无数据</div>
                }
                return items.map((item) => {
                  const pct = total > 0 ? Math.round((item.count / total) * 100) : 0
                  return (
                    <div key={item.label}>
                      <div style={{ marginBottom: '6px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                        <span
                          style={{ fontSize: '12px', fontWeight: 500, color: 'var(--text-secondary)' }}
                        >
                          {item.label}
                        </span>
                        <span
                          style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)' }}
                        >
                          {pct}% ({item.count})
                        </span>
                      </div>
                      <div
                        style={{ height: '8px', overflow: 'hidden', borderRadius: '9999px', background: 'rgba(148,163,184,0.08)' }}
                      >
                        <div
                          className="progress-bar-fill"
                          style={{
                            height: '100%',
                            borderRadius: '9999px',
                            width: progressAnimated ? `${pct}%` : '0%',
                            background: `linear-gradient(90deg, ${item.color}, ${item.color}dd)`,
                          }}
                        />
                      </div>
                    </div>
                  )
                })
              })()}
            </div>
          </div>

          {/* Severity Distribution */}
          <div
            style={{
              borderRadius: '16px',
              border: '1px solid var(--border-light)',
              background: 'var(--bg-card)',
              padding: '24px',
              boxShadow: 'var(--shadow-sm)',
            }}
          >
            <h3
              style={{ marginBottom: '16px', fontWeight: 600, fontSize: '16px', color: 'var(--text-primary)' }}
            >
              风险等级分布
            </h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              {(() => {
                const severityMap: Record<string, { label: string; color: string }> = {
                  high: { label: '高危', color: '#EF4444' },
                  medium: { label: '中危', color: '#F59E0B' },
                  low: { label: '低危', color: '#10B981' },
                  info: { label: '信息', color: '#94A3B8' },
                }
                const items = (stats?.tasks_by_severity ?? []).map((s) => ({
                  label: severityMap[s.severity]?.label ?? s.severity,
                  color: severityMap[s.severity]?.color ?? '#94A3B8',
                  count: s.count,
                }))
                const total = items.reduce((sum, i) => sum + i.count, 0)
                return items.map((item) => {
                  const pct = total > 0 ? Math.round((item.count / total) * 100) : 0
                  return (
                    <div key={item.label}>
                      <div style={{ marginBottom: '6px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <span
                            style={{
                              display: 'inline-block',
                              borderRadius: '50%',
                              width: '8px',
                              height: '8px',
                              background: item.color,
                            }}
                          />
                          <span
                            style={{ fontSize: '12px', fontWeight: 500, color: 'var(--text-secondary)' }}
                          >
                            {item.label}
                          </span>
                        </div>
                        <span
                          style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)' }}
                        >
                          {item.count} ({pct}%)
                        </span>
                      </div>
                      <div
                        style={{ height: '8px', overflow: 'hidden', borderRadius: '9999px', background: 'rgba(148,163,184,0.08)' }}
                      >
                        <div
                          className="progress-bar-fill"
                          style={{
                            height: '100%',
                            borderRadius: '9999px',
                            width: progressAnimated ? `${pct}%` : '0%',
                            background: `linear-gradient(90deg, ${item.color}, ${item.color}dd)`,
                          }}
                        />
                      </div>
                    </div>
                  )
                })
              })()}
            </div>
          </div>

          {/* Activity Summary Mini Card */}
          <div
            className={`gradient-bg${(stats?.high_severity_tasks ?? 0) > 0 ? ' animate-glow-pulse' : ''}`}
            style={{
              marginTop: '24px',
              borderRadius: '16px',
              padding: '24px',
              boxShadow: 'var(--shadow-brand)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
              <ShieldCheck size={18} style={{ color: 'white' }} />
              <span style={{ fontSize: '14px', fontWeight: 600, color: 'white' }}>安全概览</span>
            </div>
            <div style={{ color: 'rgba(255,255,255,0.9)', fontSize: '12px', lineHeight: '1.6' }}>
              共分析 <span style={{ fontWeight: 700, color: 'white' }}>{stats?.total_tasks ?? 0}</span> 个任务，
              发现 <span style={{ fontWeight: 700, color: 'white' }}>{stats?.high_severity_tasks ?? 0}</span> 个高危漏洞。
              {stats?.tasks_by_type && stats.tasks_by_type.length > 0 && (
                <>最常见类型为 {stats.tasks_by_type.sort((a, b) => b.count - a.count)[0]?.type === 'vulnerability_detection' ? '代码扫描' : '恶意分析'}。</>
              )}
            </div>
            <div style={{ marginTop: '16px' }}>
              <div style={{ marginBottom: '6px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <span style={{ fontSize: '12px', color: 'rgba(255,255,255,0.7)' }}>安全评分</span>
                <span style={{ fontSize: '12px', fontWeight: 700, color: 'white' }}>
                  {(() => {
                    const high = stats?.high_severity_tasks ?? 0
                    const total = stats?.total_tasks ?? 1
                    const score = Math.max(10, Math.round(100 - (high / total) * 100))
                    return `${score}/100`
                  })()}
                </span>
              </div>
              <div style={{ height: '8px', overflow: 'hidden', borderRadius: '9999px', background: 'rgba(255,255,255,0.2)' }}>
                <div
                  className="progress-bar-fill"
                  style={{
                    height: '100%',
                    borderRadius: '9999px',
                    background: 'var(--bg-card)',
                    width: progressAnimated ? `${(() => {
                      const high = stats?.high_severity_tasks ?? 0
                      const total = stats?.total_tasks ?? 1
                      return Math.max(10, Math.round(100 - (high / total) * 100))
                    })()}%` : '0%',
                  }}
                />
              </div>
            </div>
          </div>

          {/* Activity Timeline */}
          <div
            style={{
              marginTop: '24px',
              borderRadius: '16px',
              border: '1px solid var(--border-light)',
              background: 'var(--bg-card)',
              padding: '24px',
              boxShadow: 'var(--shadow-sm)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '16px' }}>
              <Activity size={16} style={{ color: 'var(--accent-start)' }} />
              <h3
                style={{ fontWeight: 600, fontSize: '16px', color: 'var(--text-primary)' }}
              >
                活动时间线
              </h3>
            </div>
            <div className="custom-scrollbar" style={{ maxHeight: '256px', overflowY: 'auto' }}>
              {(stats?.recent_tasks ?? []).slice(0, 6).map((task, idx) => {
                const isLast = idx === Math.min((stats?.recent_tasks?.length ?? 0) - 1, 5)
                const statusIcon = task.status === 'done'
                  ? <CheckCircle2 size={14} style={{ color: '#10B981' }} />
                  : task.status === 'analyzing'
                  ? <Loader2 size={14} className="animate-spin" style={{ color: '#5BA3FF' }} />
                  : task.status === 'failed'
                  ? <AlertTriangle size={14} style={{ color: '#EF4444' }} />
                  : <Clock size={14} style={{ color: '#94A3B8' }} />
                const statusLabel = task.status === 'done'
                  ? '分析完成'
                  : task.status === 'analyzing'
                  ? '正在分析'
                  : task.status === 'failed'
                  ? '分析失败'
                  : '等待分析'
                return (
                  <div key={task.id} style={{ display: 'flex', gap: '12px' }}>
                    {/* Timeline dot + line */}
                    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                      <div
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          borderRadius: '50%',
                          width: '28px',
                          height: '28px',
                          flexShrink: 0,
                          background: task.status === 'done'
                            ? 'rgba(16,185,129,0.1)'
                            : task.status === 'analyzing'
                            ? 'rgba(91,163,255,0.1)'
                            : task.status === 'failed'
                            ? 'rgba(239,68,68,0.1)'
                            : 'rgba(148,163,184,0.06)',
                        }}
                      >
                        {statusIcon}
                      </div>
                      {!isLast && (
                        <div
                          style={{
                            flex: 1,
                            width: '1px',
                            minHeight: '20px',
                            background: 'var(--border-light)',
                          }}
                        />
                      )}
                    </div>
                    {/* Content */}
                    <div style={{ paddingBottom: isLast ? 0 : '16px' }}>
                      <div style={{ fontSize: '12px', fontWeight: 500, color: 'var(--text-primary)' }}>
                        {task.input_path ? task.input_path.split('/').pop() : task.input_content ? `代码片段 #${task.id}` : `任务 #${task.id}`}
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '2px' }}>
                        <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                          {statusLabel}
                        </span>
                        <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>·</span>
                        <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                          {new Date(task.created_at).toLocaleString('zh-CN', {
                            month: '2-digit',
                            day: '2-digit',
                            hour: '2-digit',
                            minute: '2-digit',
                          })}
                        </span>
                      </div>
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        </div>
      </div>

      {/* ─── 数据可视化 Section ─────────────────────────── */}
      <div style={{ marginTop: '40px' }}>
        <div className="animate-slide-up" style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '24px', animationDelay: '400ms', animationFillMode: 'both' }}>
          <BarChart3 size={20} style={{ color: 'var(--accent-start)' }} />
          <h2
            style={{ fontWeight: 600, fontSize: '18px', color: 'var(--text-primary)' }}
          >
            数据可视化
          </h2>
          <div
            style={{ marginLeft: '8px', height: '1px', flex: 1, background: 'var(--border-light)' }}
          />
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '24px' }}>
          {/* Chart 1: Risk Radar */}
          <div className="animate-slide-up" style={{ animationDelay: '460ms', animationFillMode: 'both' }}>
            <RiskRadarChart data={[
              { dimension: '代码质量', score: 72, fullMark: 100 },
              { dimension: '认证', score: 85, fullMark: 100 },
              { dimension: '授权', score: 60, fullMark: 100 },
              { dimension: '数据保护', score: 45, fullMark: 100 },
              { dimension: '加密', score: 78, fullMark: 100 },
              { dimension: '日志', score: 55, fullMark: 100 },
            ]} />
          </div>
          {/* Chart 2: Vuln Type Donut */}
          <div className="animate-slide-up" style={{ animationDelay: '520ms', animationFillMode: 'both' }}>
            <VulnTypeDonutChart data={(stats?.tasks_by_type ?? []).map((t) => {
              const typeColorMap: Record<string, string> = {
                vulnerability_detection: '#5BA3FF',
                malware_analysis: '#5EEAD4',
              }
              const typeLabelMap: Record<string, string> = {
                vulnerability_detection: '代码扫描',
                malware_analysis: '恶意分析',
              }
              return { name: typeLabelMap[t.type] ?? t.type, value: t.count, color: typeColorMap[t.type] ?? '#94A3B8' }
            })} />
          </div>
          {/* Chart 3: Severity Bar */}
          <div className="animate-slide-up" style={{ animationDelay: '580ms', animationFillMode: 'both' }}>
            <SeverityBarChart data={(stats?.tasks_by_severity ?? []).map((s) => {
              const sevColorMap: Record<string, string> = {
                high: '#EF4444',
                medium: '#F59E0B',
                low: '#10B981',
                info: '#94A3B8',
              }
              const sevLabelMap: Record<string, string> = {
                high: '高危',
                medium: '中危',
                low: '低危',
                info: '信息',
              }
              return { name: sevLabelMap[s.severity] ?? s.severity, count: s.count, fill: sevColorMap[s.severity] ?? '#94A3B8' }
            })} />
          </div>
          {/* Chart 4: Task Trend */}
          <div className="animate-slide-up" style={{ animationDelay: '640ms', animationFillMode: 'both' }}>
            <TaskTrendChart data={stats?.tasks_by_day ?? []} />
          </div>
          {/* Chart 5: Success Rate */}
          <div className="animate-slide-up" style={{ animationDelay: '700ms', animationFillMode: 'both' }}>
            <TaskSuccessRateChart data={getStatusCounts()} />
          </div>
          {/* Chart 6: Duration Distribution */}
          <div className="animate-slide-up" style={{ animationDelay: '760ms', animationFillMode: 'both' }}>
            <DurationDistChart tasks={stats?.recent_tasks ?? []} />
          </div>
        </div>
      </div>
    </div>
  )
}

export default Dashboard;
