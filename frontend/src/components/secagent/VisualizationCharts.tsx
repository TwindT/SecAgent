import {
  Radar,
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
} from 'recharts'

// ─── Custom Tooltip ─────────────────────────────────
function CustomTooltip({ active, payload, label }: { active?: boolean; payload?: Array<{ name: string; value: number; color?: string }>; label?: string }) {
  if (!active || !payload || payload.length === 0) return null
  return (
    <div
      style={{
        borderRadius: '12px',
        border: '1px solid var(--border-light)',
        background: 'var(--bg-card)',
        padding: '8px 12px',
        boxShadow: 'var(--shadow-md)',
      }}
    >
      <p
        style={{
          marginBottom: '4px',
          fontSize: '12px',
          fontWeight: 500,
          color: 'var(--text-primary)',
        }}
      >
        {label}
      </p>
      {payload.map((entry, idx) => (
        <p
          key={idx}
          style={{
            fontSize: '12px',
            color: entry.color || 'var(--text-secondary)',
          }}
        >
          {entry.name}: {entry.value}
        </p>
      ))}
    </div>
  )
}

// ─── Risk Radar Chart Component ─────────────────────
interface RiskRadarChartProps {
  data: Array<{ dimension: string; score: number; fullMark?: number }>
}

export function RiskRadarChart({ data }: RiskRadarChartProps) {
  const hasData = data && data.length > 0
  return (
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
        style={{
          marginBottom: '4px',
          fontWeight: 600,
          fontSize: '16px',
          color: 'var(--text-primary)',
        }}
      >
        风险雷达图
      </h3>
      <p
        style={{
          marginBottom: '16px',
          fontSize: '12px',
          color: 'var(--text-muted)',
        }}
      >
        多维度安全评分概览
      </p>
      {hasData ? (
        <>
          <ResponsiveContainer width="100%" height={280}>
            <RadarChart cx="50%" cy="50%" outerRadius="70%" data={data}>
              <PolarGrid
                stroke="rgba(148,163,184,0.12)"
                strokeDasharray="3 3"
              />
              <PolarAngleAxis
                dataKey="dimension"
                tick={{
                  fill: '#64748B',
                  fontSize: 11,
                  fontWeight: 500,
                }}
              />
              <PolarRadiusAxis
                angle={90}
                domain={[0, 100]}
                tick={{
                  fill: '#94A3B8',
                  fontSize: 9,
                }}
                axisLine={false}
              />
              <Radar
                name="安全评分"
                dataKey="score"
                stroke="#5BA3FF"
                fill="#5BA3FF"
                fillOpacity={0.15}
                strokeWidth={2}
              />
            </RadarChart>
          </ResponsiveContainer>
          {/* Score indicators below */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '8px', marginTop: '8px' }}>
            {data.map((item) => (
              <div
                key={item.dimension}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  borderRadius: '8px',
                  padding: '6px 10px',
                  background: 'rgba(148,163,184,0.04)',
                }}
              >
                <span
                  style={{ fontSize: '10px', color: 'var(--text-secondary)' }}
                >
                  {item.dimension}
                </span>
                <span
                  style={{
                    fontSize: '10px',
                    fontWeight: 600,
                    color:
                      item.score >= 70
                        ? '#10B981'
                        : item.score >= 50
                        ? '#F59E0B'
                        : '#EF4444',
                  }}
                >
                  {item.score}
                </span>
              </div>
            ))}
          </div>
        </>
      ) : (
        <div
          style={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            height: 280,
            color: 'var(--text-muted)',
          }}
        >
          <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" style={{ marginBottom: '12px', opacity: 0.4 }}>
            <circle cx="12" cy="12" r="10" />
            <path d="M12 16v-4" />
            <path d="M12 8h.01" />
          </svg>
          <span style={{ fontSize: '13px' }}>暂无数据</span>
        </div>
      )}
    </div>
  )
}

// ─── Vulnerability Type Donut Chart ─────────────────
interface VulnTypeDonutChartProps {
  data: Array<{ name: string; value: number; color: string }>
}

export function VulnTypeDonutChart({ data }: VulnTypeDonutChartProps) {
  const hasData = data && data.length > 0
  const total = data.reduce((s, d) => s + d.value, 0)
  return (
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
        style={{
          marginBottom: '4px',
          fontWeight: 600,
          fontSize: '16px',
          color: 'var(--text-primary)',
        }}
      >
        漏洞类型分布
      </h3>
      <p
        style={{
          marginBottom: '16px',
          fontSize: '12px',
          color: 'var(--text-muted)',
        }}
      >
        按漏洞类型统计发现数量
      </p>
      {hasData ? (
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div style={{ position: 'relative', width: '140px', height: '140px', flexShrink: 0 }}>
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={data}
                  cx="50%"
                  cy="50%"
                  innerRadius={40}
                  outerRadius={65}
                  paddingAngle={3}
                  dataKey="value"
                  stroke="none"
                >
                  {data.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                {/* Center text */}
                <text
                  x="50%"
                  y="45%"
                  textAnchor="middle"
                  dominantBaseline="central"
                  fill="var(--text-primary)"
                  fontSize={22}
                  fontWeight={700}
                >
                  {total}
                </text>
                <text
                  x="50%"
                  y="62%"
                  textAnchor="middle"
                  dominantBaseline="central"
                  fill="#94A3B8"
                  fontSize={9}
                  fontWeight={500}
                >
                  总计
                </text>
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {data.map((item) => (
              <div key={item.name} style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span
                  style={{
                    display: 'inline-block',
                    width: '10px',
                    height: '10px',
                    background: item.color,
                    flexShrink: 0,
                    borderRadius: '2px',
                  }}
                />
                <span
                  style={{ flex: 1, fontSize: '12px', color: 'var(--text-secondary)' }}
                >
                  {item.name}
                </span>
                <span
                  style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)' }}
                >
                  {item.value}
                </span>
              </div>
            ))}
          </div>
        </div>
      ) : (
        <div
          style={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            height: 180,
            color: 'var(--text-muted)',
          }}
        >
          <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" style={{ marginBottom: '12px', opacity: 0.4 }}>
            <circle cx="12" cy="12" r="10" />
            <path d="M12 16v-4" />
            <path d="M12 8h.01" />
          </svg>
          <span style={{ fontSize: '13px' }}>暂无数据</span>
        </div>
      )}
    </div>
  )
}

// ─── Task Trend Chart ───────────────────────────────
interface TaskTrendChartProps {
  data: Array<{ date: string; count: number }>
}

export function TaskTrendChart({ data }: TaskTrendChartProps) {
  return (
    <div
      style={{
        borderRadius: '16px',
        border: '1px solid var(--border-light)',
        background: 'var(--bg-card)',
        padding: '24px',
        boxShadow: 'var(--shadow-sm)',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
        <div>
          <h3
            style={{
              fontWeight: 600,
              fontSize: '16px',
              color: 'var(--text-primary)',
            }}
          >
            近7天任务趋势
          </h3>
          <p
            style={{ fontSize: '12px', color: 'var(--text-muted)' }}
          >
            每日新增任务数量
          </p>
        </div>
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
            borderRadius: '8px',
            padding: '4px 10px',
            background: 'rgba(91,163,255,0.06)',
          }}
        >
          <span style={{ fontSize: '11px', fontWeight: 600, color: '#5BA3FF' }}>
            总计 {data.reduce((s, d) => s + d.count, 0)}
          </span>
        </div>
      </div>
      <ResponsiveContainer width="100%" height={220}>
        <LineChart
          data={data}
          margin={{ top: 5, right: 20, left: 0, bottom: 5 }}
        >
          <defs>
            <linearGradient id="lineGradient" x1="0" y1="0" x2="1" y2="0">
              <stop offset="0%" stopColor="#5BA3FF" />
              <stop offset="100%" stopColor="#5EEAD4" />
            </linearGradient>
            <linearGradient id="areaGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#5BA3FF" stopOpacity={0.15} />
              <stop offset="100%" stopColor="#5EEAD4" stopOpacity={0.01} />
            </linearGradient>
          </defs>
          <CartesianGrid
            strokeDasharray="3 3"
            stroke="rgba(148,163,184,0.08)"
            vertical={false}
          />
          <XAxis
            dataKey="date"
            tick={{
              fill: '#64748B',
              fontSize: 11,
              fontWeight: 500,
            }}
            axisLine={{ stroke: 'rgba(148,163,184,0.08)' }}
            tickLine={false}
          />
          <YAxis
            tick={{
              fill: '#94A3B8',
              fontSize: 10,
            }}
            axisLine={false}
            tickLine={false}
            allowDecimals={false}
          />
          <Tooltip content={<CustomTooltip />} />
          <Line
            type="monotone"
            dataKey="count"
            name="任务数"
            stroke="url(#lineGradient)"
            strokeWidth={2.5}
            dot={{ fill: '#5BA3FF', r: 4, strokeWidth: 0 }}
            activeDot={{ fill: '#5BA3FF', r: 6, strokeWidth: 2, stroke: '#fff' }}
            fill="url(#areaGradient)"
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  )
}

// ─── Severity Bar Chart ─────────────────────────────
interface SeverityBarChartProps {
  data: Array<{ name: string; count: number; fill: string }>
}

export function SeverityBarChart({ data }: SeverityBarChartProps) {
  const hasData = data && data.length > 0
  return (
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
        style={{
          marginBottom: '4px',
          fontWeight: 600,
          fontSize: '16px',
          color: 'var(--text-primary)',
        }}
      >
        严重等级分布
      </h3>
      <p
        style={{
          marginBottom: '16px',
          fontSize: '12px',
          color: 'var(--text-muted)',
        }}
      >
        按严重程度统计漏洞数量
      </p>
      {hasData ? (
        <ResponsiveContainer width="100%" height={200}>
          <BarChart
            data={data}
            barCategoryGap="30%"
            margin={{ top: 5, right: 20, left: 0, bottom: 5 }}
          >
            <CartesianGrid
              strokeDasharray="3 3"
              stroke="rgba(148,163,184,0.08)"
              vertical={false}
            />
            <XAxis
              dataKey="name"
              tick={{
                fill: '#64748B',
                fontSize: 11,
                fontWeight: 500,
              }}
              axisLine={{ stroke: 'rgba(148,163,184,0.08)' }}
              tickLine={false}
            />
            <YAxis
              tick={{
                fill: '#94A3B8',
                fontSize: 10,
              }}
              axisLine={false}
              tickLine={false}
            />
            <Tooltip content={<CustomTooltip />} />
            <Bar dataKey="count" radius={[6, 6, 0, 0]} name="数量">
              {data.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.fill} fillOpacity={0.85} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      ) : (
        <div
          style={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            height: 200,
            color: 'var(--text-muted)',
          }}
        >
          <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" style={{ marginBottom: '12px', opacity: 0.4 }}>
            <circle cx="12" cy="12" r="10" />
            <path d="M12 16v-4" />
            <path d="M12 8h.01" />
          </svg>
          <span style={{ fontSize: '13px' }}>暂无数据</span>
        </div>
      )}
    </div>
  )
}

// ─── Task Success Rate Donut Chart ──────────────────
interface TaskSuccessRateChartProps {
  data: {
    done: number
    failed: number
    analyzing: number
    pending: number
  }
}

export function TaskSuccessRateChart({ data }: TaskSuccessRateChartProps) {
  const chartData = [
    { name: '已完成', value: data.done, color: '#10B981' },
    { name: '失败', value: data.failed, color: '#EF4444' },
    { name: '分析中', value: data.analyzing, color: '#5BA3FF' },
    { name: '等待中', value: data.pending, color: '#94A3B8' },
  ].filter((d) => d.value > 0)

  const total = chartData.reduce((s, d) => s + d.value, 0)
  const successRate = total > 0 ? Math.round((data.done / total) * 100) : 0

  return (
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
        style={{
          marginBottom: '4px',
          fontWeight: 600,
          fontSize: '16px',
          color: 'var(--text-primary)',
        }}
      >
        任务成功率
      </h3>
      <p
        style={{
          marginBottom: '16px',
          fontSize: '12px',
          color: 'var(--text-muted)',
        }}
      >
        任务完成状态分布
      </p>
      <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
        <div style={{ position: 'relative', width: '140px', height: '140px', flexShrink: 0 }}>
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={chartData.length > 0 ? chartData : [{ name: '暂无', value: 1, color: '#E2E8F0' }]}
                cx="50%"
                cy="50%"
                innerRadius={40}
                outerRadius={65}
                paddingAngle={3}
                dataKey="value"
                stroke="none"
              >
                {(chartData.length > 0 ? chartData : [{ name: '暂无', value: 1, color: '#E2E8F0' }]).map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              {/* Center text */}
              <text
                x="50%"
                y="42%"
                textAnchor="middle"
                dominantBaseline="central"
                fill="var(--text-primary)"
                fontSize={24}
                fontWeight={700}
              >
                {successRate}%
              </text>
              <text
                x="50%"
                y="60%"
                textAnchor="middle"
                dominantBaseline="central"
                fill="#94A3B8"
                fontSize={9}
                fontWeight={500}
              >
                成功率
              </text>
            </PieChart>
          </ResponsiveContainer>
        </div>
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '10px' }}>
          {[
            { name: '已完成', value: data.done, color: '#10B981' },
            { name: '失败', value: data.failed, color: '#EF4444' },
            { name: '分析中', value: data.analyzing, color: '#5BA3FF' },
            { name: '等待中', value: data.pending, color: '#94A3B8' },
          ].map((item) => (
            <div key={item.name} style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span
                style={{
                  display: 'inline-block',
                  width: '10px',
                  height: '10px',
                  background: item.color,
                  flexShrink: 0,
                  borderRadius: '2px',
                }}
              />
              <span
                style={{ flex: 1, fontSize: '12px', color: 'var(--text-secondary)' }}
              >
                {item.name}
              </span>
              <span
                style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)' }}
              >
                {item.value}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

// ─── Analysis Duration Distribution Bar Chart ───────
interface DurationDistChartProps {
  tasks: Array<{ duration: string | null }>
}

export function DurationDistChart({ tasks }: DurationDistChartProps) {
  // Compute duration buckets from task data
  const buckets = { under30: 0, '30to60': 0, '1to5': 0, over5: 0 }

  tasks.forEach((task) => {
    if (!task.duration) return
    const dur = task.duration
    // Parse duration strings like "2m 30s", "45s", "1m", "5m 12s"
    let totalSeconds = 0
    const mMatch = dur.match(/(\d+)m/)
    const sMatch = dur.match(/(\d+)s/)
    if (mMatch) totalSeconds += parseInt(mMatch[1]) * 60
    if (sMatch) totalSeconds += parseInt(sMatch[1])

    if (totalSeconds === 0) return
    if (totalSeconds < 30) buckets.under30++
    else if (totalSeconds < 60) buckets['30to60']++
    else if (totalSeconds < 300) buckets['1to5']++
    else buckets.over5++
  })

  const chartData = [
    { name: '<30s', count: buckets.under30, fill: '#10B981' },
    { name: '30s-1m', count: buckets['30to60'], fill: '#5BA3FF' },
    { name: '1m-5m', count: buckets['1to5'], fill: '#F59E0B' },
    { name: '>5m', count: buckets.over5, fill: '#EF4444' },
  ]

  return (
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
        style={{
          marginBottom: '4px',
          fontWeight: 600,
          fontSize: '16px',
          color: 'var(--text-primary)',
        }}
      >
        分析耗时分布
      </h3>
      <p
        style={{
          marginBottom: '16px',
          fontSize: '12px',
          color: 'var(--text-muted)',
        }}
      >
        任务分析时长统计
      </p>
      <ResponsiveContainer width="100%" height={200}>
        <BarChart
          data={chartData}
          barCategoryGap="30%"
          margin={{ top: 5, right: 20, left: 0, bottom: 5 }}
        >
          <defs>
            <linearGradient id="durationGrad0" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#10B981" stopOpacity={0.95} />
              <stop offset="100%" stopColor="#10B981" stopOpacity={0.6} />
            </linearGradient>
            <linearGradient id="durationGrad1" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#5BA3FF" stopOpacity={0.95} />
              <stop offset="100%" stopColor="#5BA3FF" stopOpacity={0.6} />
            </linearGradient>
            <linearGradient id="durationGrad2" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#F59E0B" stopOpacity={0.95} />
              <stop offset="100%" stopColor="#F59E0B" stopOpacity={0.6} />
            </linearGradient>
            <linearGradient id="durationGrad3" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#EF4444" stopOpacity={0.95} />
              <stop offset="100%" stopColor="#EF4444" stopOpacity={0.6} />
            </linearGradient>
          </defs>
          <CartesianGrid
            strokeDasharray="3 3"
            stroke="rgba(148,163,184,0.08)"
            vertical={false}
          />
          <XAxis
            dataKey="name"
            tick={{
              fill: '#64748B',
              fontSize: 11,
              fontWeight: 500,
            }}
            axisLine={{ stroke: 'rgba(148,163,184,0.08)' }}
            tickLine={false}
          />
          <YAxis
            tick={{
              fill: '#94A3B8',
              fontSize: 10,
            }}
            axisLine={false}
            tickLine={false}
            allowDecimals={false}
          />
          <Tooltip content={<CustomTooltip />} />
          <Bar dataKey="count" radius={[6, 6, 0, 0]} name="任务数">
            {chartData.map((_, index) => (
              <Cell key={`cell-${index}`} fill={`url(#durationGrad${index})`} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}
