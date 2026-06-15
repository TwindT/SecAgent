import { useState, useEffect, useMemo } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { Modal, Spin, message } from 'antd'
import {
  Download,
  ShieldCheck,
  AlertTriangle,
  Bug,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  Clock,
  Zap,
  Shield,
  MessageSquare,
  Send,
  CheckCircle2,
  Loader2,
  AlertCircle,
  FileText,
  Copy,
  Check,
  Filter,
} from 'lucide-react'
import {
  RiskRadarChart,
  VulnTypeDonutChart,
  SeverityBarChart,
} from '../components/secagent/VisualizationCharts'
import ATTACKHeatmap, { type ATTCKTechnique } from '../components/secagent/ATTACKHeatmap'
import { getTask, sendMessage, downloadPdfReport, type TaskResponse } from '../services/api'

// ─── CWE Database ─────────────────────────────────────
interface CWEInfo {
  id: string
  name: string
  description: string
  consequences: string[]
  mitigations: string[]
}

const CWE_DATABASE: Record<string, CWEInfo> = {
  'CWE-89': {
    id: 'CWE-89',
    name: 'SQL 注入 (SQL Injection)',
    description:
      '软件使用来自上游组件的外部输入来构造 SQL 命令的全部或部分，但没有中和或错误地中和了在发送到下游组件的 SQL 命令中可能修改预期 SQL 命令语法的特殊元素。',
    consequences: [
      '攻击者可以读取、修改或删除数据库中的敏感数据',
      '可能绕过认证机制获取管理员权限',
      '可能导致整个数据库被拖库或破坏',
      '在某些配置下可能执行操作系统命令',
    ],
    mitigations: [
      '使用参数化查询（Prepared Statements）替代字符串拼接',
      '使用存储过程并避免动态 SQL',
      '对所有用户输入进行严格的白名单验证',
      '使用 ORM 框架减少原始 SQL 拼接',
      '遵循最小权限原则，限制数据库账户权限',
    ],
  },
  'CWE-79': {
    id: 'CWE-79',
    name: '跨站脚本攻击 (Cross-site Scripting, XSS)',
    description:
      '软件在写入网页之前没有中和或错误地中和了用户可控制的输入，导致恶意脚本可以在访客浏览器中执行。',
    consequences: [
      '攻击者可以窃取用户的会话 Cookie 和认证令牌',
      '可以在用户浏览器中执行任意 JavaScript 代码',
      '可能篡改网页内容进行钓鱼攻击',
      '可能传播蠕虫病毒（如社交平台上的 XSS 蠕虫）',
    ],
    mitigations: [
      '对所有用户输入进行 HTML 实体编码（转义 <, >, &, ", \'）',
      '使用内容安全策略（CSP）限制脚本执行来源',
      '使用框架内置的自动转义功能（如 React 的 JSX 转义）',
      '对 URL 参数进行验证，防止 javascript: 协议注入',
      '设置 Cookie 的 HttpOnly 和 Secure 标志',
    ],
  },
  'CWE-78': {
    id: 'CWE-78',
    name: '操作系统命令注入 (OS Command Injection)',
    description:
      '软件使用来自上游组件的外部输入来构造全部或部分操作系统命令，但没有中和或错误地中和了可能修改预期命令的特殊元素。',
    consequences: [
      '攻击者可以在服务器上执行任意操作系统命令',
      '可能完全控制受影响的服务器',
      '可能导致数据泄露、服务中断或系统破坏',
      '可能作为跳板攻击内网其他系统',
    ],
    mitigations: [
      '避免直接调用系统命令，使用语言内置库替代',
      '如果必须执行命令，使用参数化 API 而非 shell 执行',
      '对所有用户输入进行严格的白名单验证',
      '限制执行命令的进程权限（沙箱、chroot 等）',
    ],
  },
  'CWE-22': {
    id: 'CWE-22',
    name: '路径遍历 (Path Traversal)',
    description:
      '软件使用来自上游组件的外部输入来构造访问文件或目录的路径，但没有中和或错误地中和了可以导致路径指向预期目录之外的特殊元素。',
    consequences: [
      '攻击者可以读取服务器上的任意文件（如 /etc/passwd）',
      '可能获取敏感配置文件、源代码或数据库凭证',
      '在写入场景下可能覆盖关键系统文件',
      '可能导致远程代码执行（通过写入恶意文件）',
    ],
    mitigations: [
      '对用户输入的文件名进行严格的白名单验证',
      '使用 chroot 或虚拟目录限制文件访问范围',
      '解析路径后验证规范化路径是否在预期目录内',
      '避免直接将用户输入拼接到文件路径中',
    ],
  },
  'CWE-798': {
    id: 'CWE-798',
    name: '硬编码凭证 (Hard-coded Credentials)',
    description:
      '软件包含硬编码的凭证，如密码或加密密钥，用于自身入站认证或与外部组件的出站通信。',
    consequences: [
      '任何能访问源代码或二进制文件的人都能获取凭证',
      '凭证难以更换，修复需要重新编译和部署',
      '如果代码泄露（如开源项目），凭证将直接暴露',
      '可能导致系统被未授权访问',
    ],
    mitigations: [
      '使用环境变量或配置文件存储凭证，不要硬编码',
      '使用密钥管理服务（如 Vault、AWS Secrets Manager）',
      '使用 OAuth、API Key 等认证机制替代密码',
      '定期轮换凭证，并监控异常访问',
    ],
  },
  'CWE-352': {
    id: 'CWE-352',
    name: '跨站请求伪造 (Cross-Site Request Forgery, CSRF)',
    description:
      'Web 应用未验证或验证不足请求是否由用户有意发送，攻击者可以诱使受害者的浏览器向目标网站发送非预期的请求。',
    consequences: [
      '攻击者可以以受害者身份执行未授权操作',
      '可能修改账户设置、密码或绑定信息',
      '可能导致资金转移或数据删除',
      '受害者通常完全不知情',
    ],
    mitigations: [
      '实现 CSRF Token 机制，每个表单包含随机 Token',
      '使用 SameSite Cookie 属性限制跨站请求',
      '对关键操作要求二次确认（如重新输入密码）',
      '验证 Referer 或 Origin 头',
      '使用自定义请求头（如 X-Requested-With）',
    ],
  },
  'CWE-200': {
    id: 'CWE-200',
    name: '信息泄露 (Information Exposure)',
    description:
      '软件向未明确授权访问该信息的参与者暴露敏感信息。',
    consequences: [
      '泄露系统内部信息，辅助攻击者进一步攻击',
      '可能暴露数据库结构、API 密钥或内部 IP 地址',
      '错误消息可能包含堆栈跟踪或 SQL 语句',
      '违反数据保护法规（如 GDPR、PIPL）',
    ],
    mitigations: [
      '在生产环境中禁用详细错误消息和调试模式',
      '使用通用错误页面替代包含技术细节的错误信息',
      '对 API 响应进行过滤，只返回必要字段',
      '日志中避免记录敏感数据（如密码、Token）',
    ],
  },
  'CWE-611': {
    id: 'CWE-611',
    name: 'XML 外部实体注入 (XXE)',
    description:
      '软件在解析 XML 文档时允许引用外部实体，攻击者可以利用此功能访问服务器文件系统或发起 SSRF 攻击。',
    consequences: [
      '攻击者可以读取服务器上的任意文件',
      '可能发起服务器端请求伪造（SSRF）攻击内网服务',
      '可能导致拒绝服务（DoS）攻击（如 billion laughs 攻击）',
      '可能获取云环境元数据（如 AWS IAM 凭证）',
    ],
    mitigations: [
      '禁用 XML 解析器的外部实体处理功能',
      '使用 JSON 等更简单的数据格式替代 XML',
      '使用白名单验证 XML 输入的结构和内容',
      '升级 XML 解析库到安全版本',
    ],
  },
  'CWE-502': {
    id: 'CWE-502',
    name: '不安全的反序列化 (Deserialization of Untrusted Data)',
    description:
      '应用对不可信数据进行反序列化，攻击者可以通过精心构造的序列化数据来执行任意代码或操纵应用逻辑。',
    consequences: [
      '攻击者可以在服务器上执行任意代码',
      '可能绕过认证或授权逻辑',
      '可能导致拒绝服务攻击',
      '可能篡改应用内部状态和数据完整性',
    ],
    mitigations: [
      '避免对不可信数据进行反序列化',
      '使用 JSON 等简单数据格式替代复杂对象序列化',
      '对反序列化数据进行完整性校验（如数字签名）',
      '使用类型白名单限制可反序列化的类',
      '在沙箱环境中运行反序列化操作',
    ],
  },
  'CWE-918': {
    id: 'CWE-918',
    name: '服务器端请求伪造 (Server-Side Request Forgery, SSRF)',
    description:
      '服务器根据用户请求获取远程资源，但没有充分验证用户提供的 URL，导致攻击者可以使服务器向意外目标发起请求。',
    consequences: [
      '攻击者可以扫描和探测内网服务及端口',
      '可能访问云服务元数据获取临时凭证',
      '可能读取内网服务返回的敏感数据',
      '可能利用内网信任关系进行横向移动',
    ],
    mitigations: [
      '对用户提供的 URL 进行严格的白名单验证',
      '禁止请求内网 IP 地址和元数据服务地址',
      '使用网络层策略限制服务器出站请求范围',
      '在独立的网络区域发起外部请求',
      '对返回内容进行过滤，防止信息泄露',
    ],
  },
}

// ─── Helper Components ──────────────────────────────
function InfoIcon({ size = 24 }: { size?: number }) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <circle cx="12" cy="12" r="10" />
      <path d="M12 16v-4" />
      <path d="M12 8h.01" />
    </svg>
  )
}

function RiskLevelBadge({ level }: { level: string }) {
  const config: Record<string, { label: string; color: string; bg: string; icon: React.ComponentType<{ size?: number }> }> = {
    high: { label: '高危', color: '#EF4444', bg: 'rgba(239,68,68,0.08)', icon: AlertTriangle },
    medium: { label: '中危', color: '#F59E0B', bg: 'rgba(245,158,11,0.08)', icon: Zap },
    low: { label: '低危', color: '#10B981', bg: 'rgba(16,185,129,0.08)', icon: ShieldCheck },
    info: { label: '信息', color: '#94A3B8', bg: 'rgba(148,163,184,0.08)', icon: InfoIcon },
  }
  const c = config[level] || config.info
  const Icon = c.icon
  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '8px',
        borderRadius: '12px',
        padding: '8px 16px',
        fontSize: '14px',
        fontWeight: 600,
        background: c.bg,
        color: c.color,
      }}
    >
      <Icon size={16} />
      {c.label}
    </span>
  )
}

function SeverityDot({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    high: '#EF4444',
    medium: '#F59E0B',
    low: '#10B981',
    info: '#94A3B8',
  }
  return (
    <span
      style={{
        display: 'inline-block',
        borderRadius: '50%',
        flexShrink: 0,
        width: '8px',
        height: '8px',
        background: colors[severity] || '#94A3B8',
      }}
    />
  )
}

// ─── CWE Detail Modal ─────────────────────────────────
function CWEDetailModal({
  cweId,
  open,
  onCancel,
}: {
  cweId: string | null
  open: boolean
  onCancel: () => void
}) {
  const cweInfo = cweId ? CWE_DATABASE[cweId] : null

  const displayData = cweInfo || (cweId ? {
    id: cweId,
    name: cweId,
    description: '暂无该 CWE 的详细描述信息。请访问 MITRE CWE 官方页面了解更多。',
    consequences: ['请参阅 MITRE CWE 官方文档'],
    mitigations: ['请参阅 MITRE CWE 官方文档'],
  } : null)

  if (!displayData) return null

  const cweNumber = cweId?.replace('CWE-', '') || ''

  return (
    <Modal
      open={open}
      onCancel={onCancel}
      footer={null}
      width={560}
      styles={{
        body: {
          background: 'var(--bg-card)',
          borderColor: 'var(--border-light)',
          maxHeight: '85vh',
          overflowY: 'auto',
        },
      } as any}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '4px' }}>
        <span
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            borderRadius: '8px',
            padding: '4px 10px',
            fontSize: '12px',
            fontWeight: 700,
            background: 'rgba(91,163,255,0.1)',
            color: 'var(--accent-start)',
          }}
        >
          {displayData.id}
        </span>
        <span style={{ fontSize: '16px', fontWeight: 600, color: 'var(--text-primary)' }}>{displayData.name}</span>
      </div>
      <p style={{ color: 'var(--text-secondary)', marginBottom: '16px' }}>
        {displayData.id} 详细信息
      </p>

      <div style={{ marginTop: '8px', display: 'flex', flexDirection: 'column', gap: '20px' }}>
        {/* Description */}
        <div>
          <h4
            style={{
              marginBottom: '8px',
              fontSize: '12px',
              fontWeight: 600,
              textTransform: 'uppercase' as const,
              letterSpacing: '0.05em',
              color: 'var(--text-muted)',
            }}
          >
            描述
          </h4>
          <p
            style={{ fontSize: '14px', lineHeight: 1.6, color: 'var(--text-primary)' }}
          >
            {displayData.description}
          </p>
        </div>

        {/* Consequences */}
        <div>
          <h4
            style={{
              marginBottom: '8px',
              fontSize: '12px',
              fontWeight: 600,
              textTransform: 'uppercase' as const,
              letterSpacing: '0.05em',
              color: '#EF4444',
            }}
          >
            常见后果
          </h4>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {displayData.consequences.map((item, idx) => (
              <div
                key={idx}
                style={{
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: '8px',
                  borderRadius: '12px',
                  padding: '12px',
                  background: 'rgba(239,68,68,0.04)',
                  border: '1px solid rgba(239,68,68,0.1)',
                }}
              >
                <AlertTriangle
                  size={14}
                  style={{ color: '#EF4444', flexShrink: 0, marginTop: '3px' }}
                />
                <span style={{ fontSize: '14px', color: 'var(--text-primary)' }}>
                  {item}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Mitigations */}
        <div>
          <h4
            style={{
              marginBottom: '8px',
              fontSize: '12px',
              fontWeight: 600,
              textTransform: 'uppercase' as const,
              letterSpacing: '0.05em',
              color: '#10B981',
            }}
          >
            缓解措施
          </h4>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {displayData.mitigations.map((item, idx) => (
              <div
                key={idx}
                style={{
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: '8px',
                  borderRadius: '12px',
                  padding: '12px',
                  background: 'rgba(16,185,129,0.04)',
                  border: '1px solid rgba(16,185,129,0.1)',
                }}
              >
                <ShieldCheck
                  size={14}
                  style={{ color: '#10B981', flexShrink: 0, marginTop: '3px' }}
                />
                <span style={{ fontSize: '14px', color: 'var(--text-primary)' }}>
                  {item}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* External Link */}
        {cweNumber && (
          <div
            style={{ paddingTop: '12px', borderTop: '1px solid var(--border-light)' }}
          >
            <a
              href={`https://cwe.mitre.org/data/definitions/${cweNumber}.html`}
              target="_blank"
              rel="noopener noreferrer"
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '8px',
                fontSize: '14px',
                fontWeight: 500,
                color: 'var(--accent-start)',
                transition: 'opacity 0.15s',
                textDecoration: 'none',
              }}
              onMouseEnter={(e) => { e.currentTarget.style.opacity = '0.7' }}
              onMouseLeave={(e) => { e.currentTarget.style.opacity = '1' }}
            >
              <ExternalLink size={14} />
              在 MITRE CWE 查看完整信息
            </a>
          </div>
        )}
      </div>
    </Modal>
  )
}

// ─── Types for parsed result ─────────────────────────
interface ParsedVulnerability {
  title: string
  severity: string
  cwe: string
  location: string
  description: string
  codeSnippet: string
  fixSuggestion: string
}

interface ParsedAttackTechnique {
  id: string
  name: string
  tactic: string
}

interface ParsedResult {
  THOUGHT?: string
  VULNERABILITIES?: ParsedVulnerability[]
  SAFE_CODE?: string | Array<{ location: string; description: string }>
  ATTACK_TECHNIQUES?: ParsedAttackTechnique[]
  SUMMARY?: string
  rawAnalysis?: string
}

interface ChatMessage {
  id: string
  role: 'user' | 'agent'
  content: string
  time: string
}

// ─── Task type display labels ────────────────────────
const taskTypeLabels: Record<string, string> = {
  code_scan: '代码漏洞检测',
  malware_analysis: '恶意代码分析',
  vulnerability_detection: '代码漏洞检测',
}

// ─── Severity filter options ─────────────────────────
const severityFilterOptions = [
  { key: 'all', label: '全部' },
  { key: 'high', label: '高危' },
  { key: 'medium', label: '中危' },
  { key: 'low', label: '低危' },
  { key: 'info', label: '信息' },
] as const

// ─── Main Component ─────────────────────────────────
const Report = () => {
  const { taskId } = useParams<{ taskId: string }>()
  const navigate = useNavigate()

  // ─── API state ───────────────────────────────────
  const [task, setTask] = useState<TaskResponse | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // ─── UI state ────────────────────────────────────
  const [expandedVulns, setExpandedVulns] = useState<Set<string>>(new Set())
  const [chatInput, setChatInput] = useState('')
  const [messages, setMessages] = useState<ChatMessage[]>([])
  const [isChatTyping, setIsChatTyping] = useState(false)
  const [chatError, setChatError] = useState<string | null>(null)

  // ─── Enhancement state ───────────────────────────
  const [cweModalOpen, setCweModalOpen] = useState(false)
  const [selectedCweId, setSelectedCweId] = useState<string | null>(null)
  const [codeCopied, setCodeCopied] = useState(false)
  const [severityFilter, setSeverityFilter] = useState<string>('all')

  // ─── Fetch task data on mount ────────────────────
  useEffect(() => {
    if (!taskId) {
      setIsLoading(false)
      return
    }

    async function loadTask() {
      try {
        setIsLoading(true)
        setError(null)
        const res = await getTask(Number(taskId))
        const fetchedTask = res.data
        setTask(fetchedTask)

        // Initialize chat messages from existing conversations if available
        // Note: TaskResponse does not have conversations field in current api.ts,
        // but we keep this for future compatibility
        if ((fetchedTask as any).conversations && (fetchedTask as any).conversations.length > 0) {
          setMessages(
            (fetchedTask as any).conversations.map((c: any) => ({
              id: c.id,
              role: c.role,
              content: c.content,
              time: new Date(c.createdAt).toLocaleTimeString('zh-CN', {
                hour: '2-digit',
                minute: '2-digit',
              }),
            }))
          )
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : '加载报告失败')
      } finally {
        setIsLoading(false)
      }
    }
    loadTask()
  }, [taskId])

  // ─── Parse resultJson ────────────────────────────
  const resultData = useMemo<ParsedResult | null>(() => {
    if (!task?.result_json) return null
    try {
      return JSON.parse(task.result_json) as ParsedResult
    } catch {
      return null
    }
  }, [task?.result_json])

  // ─── Derived display data ────────────────────────
  const vulnerabilities = useMemo(() => {
    if (!resultData?.VULNERABILITIES) return []
    return resultData.VULNERABILITIES
  }, [resultData])

  const safeCode = useMemo(() => {
    if (!resultData?.SAFE_CODE) return []
    const sc = resultData.SAFE_CODE
    if (typeof sc === 'string') {
      return [{ location: '安全代码', description: sc }]
    }
    if (Array.isArray(sc)) {
      return sc.map((item, idx) =>
        typeof item === 'string'
          ? { location: `参考 ${idx + 1}`, description: item }
          : { location: item.location || `参考 ${idx + 1}`, description: item.description || '' }
      )
    }
    return []
  }, [resultData])

  const attckTechniques = useMemo(() => {
    if (!resultData?.ATTACK_TECHNIQUES) return []
    return resultData.ATTACK_TECHNIQUES
  }, [resultData])

  // Map ParsedAttackTechnique[] to ATTCKTechnique[] for heatmap
  const heatmapTechniques = useMemo<ATTCKTechnique[]>(() => {
    if (!attckTechniques.length) return []
    return attckTechniques.map((tech) => ({
      id: tech.id,
      name: tech.name,
      tactic: tech.tactic,
      confidence: 70,
    }))
  }, [attckTechniques])

  const summary = useMemo(() => {
    if (!resultData) return null
    return resultData.SUMMARY || resultData.rawAnalysis || null
  }, [resultData])

  const riskLevel = (task as any)?.severity || 'info'
  const analyzedAt = task?.updated_at
    ? new Date(task.updated_at).toLocaleString('zh-CN', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      })
    : '--'
  const duration = (task as any)?.duration || '--'
  const vulnCount = (task as any)?.vulnCount ?? vulnerabilities.length
  const typeLabel = taskTypeLabels[task?.type || ''] || task?.type || '未知类型'

  // ─── Filtered vulnerabilities ────────────────────
  const filteredVulnerabilities = useMemo(() => {
    if (severityFilter === 'all') return vulnerabilities
    return vulnerabilities.filter((v) => (v.severity || 'info') === severityFilter)
  }, [vulnerabilities, severityFilter])

  // ─── Severity counts ─────────────────────────────
  const severityCounts = useMemo(() => {
    const counts: Record<string, number> = { all: vulnerabilities.length, high: 0, medium: 0, low: 0, info: 0 }
    for (const v of vulnerabilities) {
      const sev = v.severity || 'info'
      counts[sev] = (counts[sev] || 0) + 1
    }
    return counts
  }, [vulnerabilities])

  // ─── Toggle all vulns ────────────────────────────
  const allExpanded = filteredVulnerabilities.length > 0 &&
    filteredVulnerabilities.every((_, idx) => expandedVulns.has(`VULN-${String(idx + 1).padStart(3, '0')}`))

  const toggleAllVulns = () => {
    if (allExpanded) {
      setExpandedVulns(new Set())
    } else {
      const newSet = new Set<string>()
      filteredVulnerabilities.forEach((_, idx) => {
        newSet.add(`VULN-${String(idx + 1).padStart(3, '0')}`)
      })
      setExpandedVulns(newSet)
    }
  }

  // ─── Copy safe code handler ──────────────────────
  const handleCopyCode = () => {
    const codeText = safeCode
      .map((item) => `// ${item.location}\n${item.description}`)
      .join('\n\n')
    navigator.clipboard.writeText(codeText).then(() => {
      setCodeCopied(true)
      message.success('代码已复制到剪贴板')
      setTimeout(() => setCodeCopied(false), 2000)
    }).catch(() => {
      message.error('复制失败，请手动复制')
    })
  }

  // ─── CWE modal handler ───────────────────────────
  const handleOpenCweModal = (cweId: string) => {
    setSelectedCweId(cweId)
    setCweModalOpen(true)
  }

  // ─── Export handler ──────────────────────────────
  const handleExport = () => {
    if (!taskId) {
      message.error('导出失败：未选择分析任务')
      return
    }
    message.success('正在生成报告，报告将开始下载')
    downloadPdfReport(Number(taskId)).then((res) => {
      const url = window.URL.createObjectURL(new Blob([res.data]))
      const link = document.createElement('a')
      link.href = url
      link.setAttribute('download', `report_${taskId}.pdf`)
      document.body.appendChild(link)
      link.click()
      link.remove()
      window.URL.revokeObjectURL(url)
    }).catch(() => {
      message.error('导出失败，请稍后重试')
    })
  }

  // ─── Chat handler ────────────────────────────────
  const handleSendMessage = async () => {
    if (!chatInput.trim() || isChatTyping || !taskId) return

    const userMsg: ChatMessage = {
      id: `${Date.now()}`,
      role: 'user',
      content: chatInput,
      time: new Date().toLocaleTimeString('zh-CN', {
        hour: '2-digit',
        minute: '2-digit',
      }),
    }
    setMessages((prev) => [...prev, userMsg])
    setChatInput('')
    setIsChatTyping(true)
    setChatError(null)

    try {
      const res = await sendMessage(Number(taskId), { message: userMsg.content })
      const data = res.data
      const agentMsg: ChatMessage = {
        id: `${Date.now() + 1}`,
        role: 'agent',
        content: data.reply,
        time: new Date().toLocaleTimeString('zh-CN', {
          hour: '2-digit',
          minute: '2-digit',
        }),
      }
      setMessages((prev) => [...prev, agentMsg])
    } catch (err) {
      setChatError(err instanceof Error ? err.message : '发送失败，请重试')
      message.error('发送失败，请稍后重试')
    } finally {
      setIsChatTyping(false)
    }
  }

  // ─── Severity color maps ─────────────────────────
  const severityColors: Record<string, string> = {
    high: '#EF4444',
    medium: '#F59E0B',
    low: '#10B981',
    info: '#94A3B8',
  }
  const severityBgColors: Record<string, string> = {
    high: 'rgba(239,68,68,0.06)',
    medium: 'rgba(245,158,11,0.06)',
    low: 'rgba(16,185,129,0.06)',
    info: 'rgba(148,163,184,0.06)',
  }
  const severityBorderColors: Record<string, string> = {
    high: 'rgba(239,68,68,0.2)',
    medium: 'rgba(245,158,11,0.2)',
    low: 'rgba(16,185,129,0.2)',
    info: 'rgba(148,163,184,0.2)',
  }
  const severityLabels: Record<string, string> = {
    high: '高危',
    medium: '中危',
    low: '低危',
    info: '信息',
  }

  // ─── Loading state ───────────────────────────────
  if (isLoading) {
    return (
      <div style={{ margin: '0 auto', width: '100%', maxWidth: '1200px', padding: '24px 16px' }}>
        <div style={{ marginBottom: '24px' }}>
          <div
            className="animate-pulse"
            style={{ width: '200px', height: '32px', borderRadius: '8px', background: 'rgba(148,163,184,0.08)' }}
          />
          <div
            className="animate-pulse"
            style={{ marginTop: '8px', width: '280px', height: '16px', borderRadius: '8px', background: 'rgba(148,163,184,0.06)' }}
          />
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px', marginBottom: '16px' }}>
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} style={{ borderRadius: '16px', border: '1px solid var(--border-light)', padding: '16px', background: 'var(--bg-card)' }}>
              <Spin />
            </div>
          ))}
        </div>
        <div style={{ borderRadius: '16px', border: '1px solid var(--border-light)', padding: '24px', background: 'var(--bg-card)' }}>
          <Spin />
        </div>
      </div>
    )
  }

  // ─── Empty state (no taskId) ──────────────────────
  if (!taskId) {
    return (
      <div style={{ margin: '0 auto', width: '100%', maxWidth: '1200px', padding: '24px 16px' }}>
        <div className="animate-slide-up" style={{ marginBottom: '24px' }}>
          <h1
            style={{ fontWeight: 600, fontSize: '28px', lineHeight: 1.3, color: 'var(--text-primary)' }}
          >
            分析报告
          </h1>
          <p
            style={{ marginTop: '4px', fontSize: '14px', color: 'var(--text-secondary)' }}
          >
            查看详细的安全分析报告与漏洞信息
          </p>
        </div>
        <div
          style={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            borderRadius: '16px',
            border: '1px solid var(--border-light)',
            background: 'var(--bg-card)',
            padding: '48px',
            boxShadow: 'var(--shadow-sm)',
          }}
        >
          <FileText
            size={48}
            style={{ color: 'var(--text-muted)', marginBottom: '16px' }}
          />
          <h3
            style={{ fontWeight: 600, fontSize: '18px', color: 'var(--text-primary)', marginBottom: '8px' }}
          >
            尚未选择分析报告
          </h3>
          <p
            style={{ marginBottom: '24px', textAlign: 'center', fontSize: '14px', color: 'var(--text-secondary)', maxWidth: '400px' }}
          >
            请先提交代码进行分析，或在历史记录中选择已完成的任务查看报告。
          </p>
          <div style={{ display: 'flex', gap: '12px' }}>
            <button
              onClick={() => navigate('/submit')}
              style={{
                background: 'var(--accent-gradient)',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                borderRadius: '12px',
                padding: '10px 20px',
                fontSize: '14px',
                fontWeight: 500,
                color: 'white',
                border: 'none',
                cursor: 'pointer',
                boxShadow: 'var(--shadow-brand)',
                transition: 'opacity 0.15s',
              }}
              onMouseEnter={(e) => { e.currentTarget.style.opacity = '0.9' }}
              onMouseLeave={(e) => { e.currentTarget.style.opacity = '1' }}
            >
              提交分析任务
            </button>
            <button
              onClick={() => navigate('/history')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                borderRadius: '12px',
                border: '1px solid var(--border-normal)',
                padding: '10px 20px',
                fontSize: '14px',
                fontWeight: 500,
                color: 'var(--text-primary)',
                background: 'transparent',
                cursor: 'pointer',
                transition: 'background 0.15s',
              }}
              onMouseEnter={(e) => { e.currentTarget.style.background = 'rgba(0,0,0,0.02)' }}
              onMouseLeave={(e) => { e.currentTarget.style.background = 'transparent' }}
            >
              查看历史记录
            </button>
          </div>
        </div>
      </div>
    )
  }

  // ─── Error state ─────────────────────────────────
  if (error) {
    return (
      <div style={{ margin: '0 auto', width: '100%', maxWidth: '1200px', padding: '24px 16px' }}>
        <div
          style={{
            display: 'flex',
            alignItems: 'flex-start',
            gap: '16px',
            borderRadius: '16px',
            border: '1px solid rgba(239,68,68,0.2)',
            padding: '24px',
            background: 'rgba(239,68,68,0.04)',
          }}
        >
          <AlertCircle size={20} style={{ color: '#EF4444', flexShrink: 0, marginTop: '2px' }} />
          <div>
            <h3 style={{ fontWeight: 600, fontSize: '16px', color: '#EF4444' }}>
              加载报告失败
            </h3>
            <p style={{ marginTop: '4px', fontSize: '14px', color: 'var(--text-secondary)' }}>
              {error}
            </p>
            <div style={{ marginTop: '16px', display: 'flex', gap: '12px' }}>
              <button
                onClick={() => navigate('/submit')}
                style={{
                  background: 'var(--accent-gradient)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  borderRadius: '12px',
                  padding: '8px 16px',
                  fontSize: '14px',
                  fontWeight: 500,
                  color: 'white',
                  border: 'none',
                  cursor: 'pointer',
                  boxShadow: 'var(--shadow-brand)',
                  transition: 'opacity 0.15s',
                }}
                onMouseEnter={(e) => { e.currentTarget.style.opacity = '0.9' }}
                onMouseLeave={(e) => { e.currentTarget.style.opacity = '1' }}
              >
                提交分析任务
              </button>
              <button
                onClick={() => navigate('/history')}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  borderRadius: '12px',
                  border: '1px solid var(--border-normal)',
                  padding: '8px 16px',
                  fontSize: '14px',
                  fontWeight: 500,
                  color: 'var(--text-primary)',
                  background: 'transparent',
                  cursor: 'pointer',
                  transition: 'background 0.15s',
                }}
                onMouseEnter={(e) => { e.currentTarget.style.background = 'rgba(0,0,0,0.02)' }}
                onMouseLeave={(e) => { e.currentTarget.style.background = 'transparent' }}
              >
                查看历史记录
              </button>
            </div>
          </div>
        </div>
      </div>
    )
  }

  // ─── Task not done yet ───────────────────────────
  if (task?.status === 'pending') {
    return (
      <div style={{ margin: '0 auto', width: '100%', maxWidth: '1200px', padding: '24px 16px' }}>
        <div
          style={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '64px 24px',
            borderRadius: '16px',
            border: '1px solid var(--border-light)',
            background: 'var(--bg-card)',
            boxShadow: 'var(--shadow-sm)',
          }}
        >
          <Clock size={48} style={{ color: 'var(--text-muted)', marginBottom: '16px' }} />
          <h3 style={{ fontWeight: 600, fontSize: '18px', color: 'var(--text-primary)', marginBottom: '8px' }}>
            分析尚未开始
          </h3>
          <p style={{ fontSize: '14px', color: 'var(--text-secondary)' }}>
            该任务正在等待分析，请稍后再来查看报告。
          </p>
        </div>
      </div>
    )
  }

  if (task?.status === 'analyzing') {
    return (
      <div style={{ margin: '0 auto', width: '100%', maxWidth: '1200px', padding: '24px 16px' }}>
        <div
          style={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '64px 24px',
            borderRadius: '16px',
            border: '1px solid var(--border-light)',
            background: 'var(--bg-card)',
            boxShadow: 'var(--shadow-sm)',
          }}
        >
          <Loader2 size={48} className="animate-spin" style={{ color: 'var(--accent-start)', marginBottom: '16px' }} />
          <h3 style={{ fontWeight: 600, fontSize: '18px', color: 'var(--text-primary)', marginBottom: '8px' }}>
            分析进行中
          </h3>
          <p style={{ fontSize: '14px', color: 'var(--text-secondary)' }}>
            代码安全分析正在执行，请稍候返回查看完整报告。
          </p>
        </div>
      </div>
    )
  }

  if (task?.status === 'failed') {
    return (
      <div style={{ margin: '0 auto', width: '100%', maxWidth: '1200px', padding: '24px 16px' }}>
        <div
          style={{
            display: 'flex',
            alignItems: 'flex-start',
            gap: '16px',
            borderRadius: '16px',
            border: '1px solid rgba(239,68,68,0.2)',
            padding: '24px',
            background: 'rgba(239,68,68,0.04)',
          }}
        >
          <AlertCircle size={20} style={{ color: '#EF4444', flexShrink: 0, marginTop: '2px' }} />
          <div>
            <h3 style={{ fontWeight: 600, fontSize: '16px', color: '#EF4444' }}>
              分析失败
            </h3>
            <p style={{ marginTop: '4px', fontSize: '14px', color: 'var(--text-secondary)' }}>
              该任务在分析过程中出现错误，请重新提交分析。
            </p>
          </div>
        </div>
      </div>
    )
  }

  // ─── No result data ──────────────────────────────
  if (!resultData && task?.status === 'done') {
    return (
      <div style={{ margin: '0 auto', width: '100%', maxWidth: '1200px', padding: '24px 16px' }}>
        <div
          style={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '64px 24px',
            borderRadius: '16px',
            border: '1px solid var(--border-light)',
            background: 'var(--bg-card)',
            boxShadow: 'var(--shadow-sm)',
          }}
        >
          <FileText size={48} style={{ color: 'var(--text-muted)', marginBottom: '16px' }} />
          <h3 style={{ fontWeight: 600, fontSize: '18px', color: 'var(--text-primary)', marginBottom: '8px' }}>
            暂无分析报告
          </h3>
          <p style={{ fontSize: '14px', color: 'var(--text-secondary)' }}>
            任务已完成但尚未生成分析报告数据。
          </p>
        </div>
      </div>
    )
  }

  // ─── Main Report Content ─────────────────────────
  return (
    <div style={{ margin: '0 auto', width: '100%', maxWidth: '1200px', padding: '24px 16px' }}>
      {/* Report Header */}
      <div className="animate-slide-up" style={{ marginBottom: '24px' }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap' as const, gap: '16px' }}>
          <div>
            <h1
              style={{ fontWeight: 600, fontSize: '28px', lineHeight: 1.3, color: 'var(--text-primary)' }}
            >
              分析报告
            </h1>
            <p
              style={{ marginTop: '4px', fontSize: '14px', color: 'var(--text-secondary)' }}
            >
              任务 {taskId} · {task?.input_path || '--'} · {typeLabel}
            </p>
          </div>
          <button
            onClick={handleExport}
            style={{
              background: 'var(--accent-gradient)',
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              borderRadius: '12px',
              padding: '10px 20px',
              fontSize: '14px',
              fontWeight: 500,
              color: 'white',
              border: 'none',
              cursor: 'pointer',
              boxShadow: 'var(--shadow-brand)',
              transition: 'opacity 0.15s',
            }}
            onMouseEnter={(e) => { e.currentTarget.style.opacity = '0.9' }}
            onMouseLeave={(e) => { e.currentTarget.style.opacity = '1' }}
          >
            <Download size={16} />
            导出 PDF 报告
          </button>
        </div>
      </div>

      {/* Report Info Bar */}
      <div
        className="animate-slide-up"
        style={{
          marginBottom: '24px',
          display: 'grid',
          gridTemplateColumns: 'repeat(4, 1fr)',
          gap: '16px',
          animationDelay: '60ms',
          animationFillMode: 'both',
        }}
      >
        {[
          { label: '分析时间', value: analyzedAt, icon: Clock },
          { label: '分析耗时', value: duration, icon: Zap },
          { label: '风险等级', value: <RiskLevelBadge level={riskLevel} />, icon: Shield },
          { label: '漏洞数量', value: String(vulnCount), icon: Bug },
        ].map((item) => {
          const Icon = item.icon
          return (
            <div
              key={item.label}
              style={{
                borderRadius: '16px',
                border: '1px solid var(--border-light)',
                background: 'var(--bg-card)',
                padding: '16px',
                boxShadow: 'var(--shadow-sm)',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                <Icon size={14} style={{ color: 'var(--text-muted)' }} />
                <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>{item.label}</span>
              </div>
              {typeof item.value === 'string' ? (
                <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)' }}>
                  {item.value}
                </div>
              ) : (
                item.value
              )}
            </div>
          )
        })}
      </div>

      {/* Summary Card */}
      {summary && (
        <div
          className="animate-slide-up"
          style={{
            marginBottom: '24px',
            borderRadius: '16px',
            border: '1px solid var(--border-light)',
            background: 'var(--bg-card)',
            padding: '24px',
            boxShadow: 'var(--shadow-sm)',
            animationDelay: '120ms',
            animationFillMode: 'both',
          }}
        >
          <h2
            style={{ marginBottom: '12px', fontWeight: 600, fontSize: '18px', color: 'var(--text-primary)' }}
          >
            分析摘要
          </h2>
          <p
            style={{ fontSize: '14px', lineHeight: 1.6, color: 'var(--text-secondary)' }}
          >
            {summary}
          </p>
        </div>
      )}

      {/* Raw analysis result fallback when structured data is unavailable */}
      {!summary && resultData?.rawAnalysis && (
        <div
          className="animate-slide-up"
          style={{
            marginBottom: '24px',
            borderRadius: '16px',
            border: '1px solid var(--border-light)',
            background: 'var(--bg-card)',
            padding: '24px',
            boxShadow: 'var(--shadow-sm)',
            animationDelay: '120ms',
            animationFillMode: 'both',
          }}
        >
          <h2
            style={{ marginBottom: '12px', fontWeight: 600, fontSize: '18px', color: 'var(--text-primary)' }}
          >
            原始分析结果
          </h2>
          <pre
            className="custom-scrollbar"
            style={{
              overflowX: 'auto',
              whiteSpace: 'pre-wrap',
              fontSize: '14px',
              lineHeight: 1.6,
              color: 'var(--text-secondary)',
              fontFamily: "'JetBrains Mono', 'Fira Code', Consolas, monospace",
            }}
          >
            {resultData.rawAnalysis}
          </pre>
        </div>
      )}

      {/* Vulnerabilities List */}
      <div
        className="animate-slide-up"
        style={{ marginBottom: '24px', animationDelay: '180ms', animationFillMode: 'both' }}
      >
        {vulnerabilities.length > 0 ? (
          <>
            {/* Vulnerability section header with expand/collapse all and severity filter */}
            <div style={{ marginBottom: '16px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <h2
                  style={{ fontWeight: 600, fontSize: '18px', color: 'var(--text-primary)' }}
                >
                  发现漏洞 ({vulnerabilities.length})
                </h2>
                <button
                  onClick={toggleAllVulns}
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '6px',
                    borderRadius: '12px',
                    border: '1px solid var(--border-normal)',
                    padding: '6px 12px',
                    fontSize: '12px',
                    fontWeight: 500,
                    color: 'var(--text-secondary)',
                    background: 'transparent',
                    cursor: 'pointer',
                    transition: 'background 0.15s',
                  }}
                  onMouseEnter={(e) => { e.currentTarget.style.background = 'rgba(0,0,0,0.02)' }}
                  onMouseLeave={(e) => { e.currentTarget.style.background = 'transparent' }}
                >
                  {allExpanded ? (
                    <>
                      <ChevronUp size={14} />
                      全部收起
                    </>
                  ) : (
                    <>
                      <ChevronDown size={14} />
                      全部展开
                    </>
                  )}
                </button>
              </div>

              {/* Severity filter pills */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' as const }}>
                <Filter size={14} style={{ color: 'var(--text-muted)', marginRight: '4px' }} />
                {severityFilterOptions.map((opt) => {
                  const isActive = severityFilter === opt.key
                  const count = severityCounts[opt.key] || 0
                  return (
                    <button
                      key={opt.key}
                      onClick={() => setSeverityFilter(opt.key)}
                      style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '6px',
                        borderRadius: '12px',
                        padding: '6px 12px',
                        fontSize: '12px',
                        fontWeight: 500,
                        transition: 'all 0.2s',
                        background: isActive ? 'var(--accent-gradient)' : 'var(--bg-page)',
                        color: isActive ? 'white' : 'var(--text-secondary)',
                        border: isActive ? 'none' : '1px solid var(--border-normal)',
                        boxShadow: isActive ? 'var(--shadow-brand)' : 'none',
                        cursor: 'pointer',
                      }}
                    >
                      {opt.label}
                      <span
                        style={{
                          display: 'inline-flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          minWidth: '18px',
                          height: '18px',
                          fontSize: '10px',
                          fontWeight: 600,
                          background: isActive ? 'rgba(255,255,255,0.2)' : 'rgba(148,163,184,0.1)',
                          color: isActive ? 'white' : 'var(--text-muted)',
                          padding: '0 4px',
                          borderRadius: '50%',
                        }}
                      >
                        {count}
                      </span>
                    </button>
                  )
                })}
              </div>
            </div>

            {/* Filtered vulnerability list */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              {filteredVulnerabilities.length > 0 ? (
                filteredVulnerabilities.map((vuln, idx) => {
                  const originalIdx = vulnerabilities.indexOf(vuln)
                  const vulnId = `VULN-${String(originalIdx + 1).padStart(3, '0')}`
                  const isExpanded = expandedVulns.has(vulnId)
                  const sev = vuln.severity || 'info'

                  return (
                    <div
                      key={vulnId}
                      className={`vuln-card-severity severity-${sev} stagger-card`}
                      style={{
                        overflow: 'hidden',
                        borderRadius: '16px',
                        border: '1px solid',
                        borderColor: isExpanded
                          ? severityBorderColors[sev]
                          : 'var(--border-light)',
                        boxShadow: 'var(--shadow-sm)',
                        transition: 'all 0.2s',
                        animationDelay: `${idx * 80}ms`,
                      }}
                    >
                      {/* Vuln Header */}
                      <button
                        onClick={() => {
                          setExpandedVulns((prev) => {
                            const newSet = new Set(prev)
                            if (newSet.has(vulnId)) {
                              newSet.delete(vulnId)
                            } else {
                              newSet.add(vulnId)
                            }
                            return newSet
                          })
                        }}
                        style={{
                          display: 'flex',
                          width: '100%',
                          alignItems: 'center',
                          gap: '16px',
                          padding: '16px 20px',
                          textAlign: 'left',
                          background: 'transparent',
                          border: 'none',
                          cursor: 'pointer',
                          color: 'inherit',
                        }}
                      >
                        <SeverityDot severity={sev} />
                        <div style={{ flex: 1, minWidth: 0 }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' as const }}>
                            <span
                              style={{ fontWeight: 500, fontSize: '14px', color: 'var(--text-primary)' }}
                            >
                              {vuln.title}
                            </span>
                            <span
                              style={{
                                borderRadius: '8px',
                                padding: '2px 8px',
                                fontSize: '12px',
                                fontWeight: 500,
                                background: severityBgColors[sev],
                                color: severityColors[sev],
                              }}
                            >
                              {severityLabels[sev] || '信息'}
                            </span>
                            {vuln.cwe && (
                              <button
                                onClick={(e) => {
                                  e.stopPropagation()
                                  handleOpenCweModal(vuln.cwe)
                                }}
                                style={{
                                  display: 'inline-flex',
                                  alignItems: 'center',
                                  gap: '4px',
                                  fontSize: '12px',
                                  fontWeight: 500,
                                  color: 'var(--accent-start)',
                                  background: 'rgba(91,163,255,0.06)',
                                  borderRadius: '8px',
                                  padding: '2px 8px',
                                  border: 'none',
                                  cursor: 'pointer',
                                  transition: 'opacity 0.15s',
                                }}
                                onMouseEnter={(e) => { e.currentTarget.style.opacity = '0.7' }}
                                onMouseLeave={(e) => { e.currentTarget.style.opacity = '1' }}
                                title="查看 CWE 详情"
                              >
                                {vuln.cwe}
                                <ExternalLink size={10} />
                              </button>
                            )}
                          </div>
                          <div
                            style={{ marginTop: '2px', fontSize: '12px', color: 'var(--text-muted)' }}
                          >
                            {vuln.location || '--'}
                          </div>
                        </div>
                        {isExpanded ? (
                          <ChevronUp size={16} style={{ color: 'var(--text-muted)' }} />
                        ) : (
                          <ChevronDown size={16} style={{ color: 'var(--text-muted)' }} />
                        )}
                      </button>

                      {/* Vuln Detail */}
                      {isExpanded && (
                        <div
                          className="expandable-content"
                          style={{
                            borderTop: '1px solid var(--border-light)',
                            padding: '16px 20px 20px',
                          }}
                        >
                          <p
                            style={{ marginBottom: '16px', fontSize: '14px', lineHeight: 1.6, color: 'var(--text-primary)' }}
                          >
                            {vuln.description}
                          </p>

                          {/* Code Snippet */}
                          {vuln.codeSnippet && (
                            <div style={{ marginBottom: '16px' }}>
                              <div
                                style={{ marginBottom: '8px', fontSize: '12px', fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.05em', color: 'var(--text-secondary)' }}
                              >
                                问题代码
                              </div>
                              <div
                                style={{
                                  overflow: 'hidden',
                                  borderRadius: '12px',
                                  border: '1px solid rgba(239,68,68,0.1)',
                                  background: 'rgba(239,68,68,0.02)',
                                }}
                              >
                                <pre
                                  className="custom-scrollbar"
                                  style={{
                                    overflowX: 'auto',
                                    padding: '16px',
                                    fontSize: '12px',
                                    lineHeight: 1.6,
                                    fontFamily: "'JetBrains Mono', 'Fira Code', Consolas, monospace",
                                    color: 'var(--text-primary)',
                                    margin: 0,
                                  }}
                                >
                                  {vuln.codeSnippet}
                                </pre>
                              </div>
                            </div>
                          )}

                          {/* Fix Suggestion */}
                          {vuln.fixSuggestion && (
                            <div>
                              <div
                                style={{ marginBottom: '8px', fontSize: '12px', fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.05em', color: '#10B981' }}
                              >
                                修复建议
                              </div>
                              <div
                                style={{
                                  overflow: 'hidden',
                                  borderRadius: '12px',
                                  border: '1px solid rgba(16,185,129,0.1)',
                                  background: 'rgba(16,185,129,0.02)',
                                }}
                              >
                                <pre
                                  className="custom-scrollbar"
                                  style={{
                                    overflowX: 'auto',
                                    padding: '16px',
                                    fontSize: '12px',
                                    lineHeight: 1.6,
                                    fontFamily: "'JetBrains Mono', 'Fira Code', Consolas, monospace",
                                    color: 'var(--text-primary)',
                                    margin: 0,
                                  }}
                                >
                                  {vuln.fixSuggestion}
                                </pre>
                              </div>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  )
                })
              ) : (
                <div
                  style={{
                    borderRadius: '16px',
                    border: '1px solid var(--border-light)',
                    background: 'var(--bg-card)',
                    padding: '24px',
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'center',
                    justifyContent: 'center',
                    boxShadow: 'var(--shadow-sm)',
                  }}
                >
                  <Filter size={32} style={{ color: 'var(--text-muted)', marginBottom: '8px' }} />
                  <p style={{ fontSize: '14px', fontWeight: 500, color: 'var(--text-secondary)' }}>
                    当前筛选条件下无漏洞
                  </p>
                  <button
                    onClick={() => setSeverityFilter('all')}
                    style={{ marginTop: '8px', fontSize: '12px', fontWeight: 500, color: 'var(--accent-start)', background: 'none', border: 'none', cursor: 'pointer' }}
                  >
                    查看全部漏洞
                  </button>
                </div>
              )}
            </div>
          </>
        ) : (
          <div
            style={{
              borderRadius: '16px',
              border: '1px solid rgba(16,185,129,0.15)',
              background: 'var(--bg-card)',
              padding: '32px',
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              boxShadow: 'var(--shadow-sm)',
            }}
          >
            <CheckCircle2 size={40} style={{ color: '#10B981', marginBottom: '12px' }} />
            <h3 style={{ fontWeight: 600, fontSize: '18px', color: '#10B981' }}>
              未发现安全漏洞
            </h3>
            <p style={{ marginTop: '4px', fontSize: '14px', color: 'var(--text-secondary)' }}>
              该代码未检测到安全漏洞，代码质量良好。
            </p>
          </div>
        )}
      </div>

      {/* Safe Code Section */}
      {safeCode.length > 0 && (
        <div
          className="animate-slide-up"
          style={{
            marginBottom: '24px',
            animationDelay: '240ms',
            animationFillMode: 'both',
          }}
        >
          <h2
            style={{ marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '8px', fontWeight: 600, fontSize: '18px', color: '#10B981' }}
          >
            <ShieldCheck size={20} />
            安全代码参考
          </h2>
          <div className="code-block-dark" style={{ position: 'relative' }}>
            <div className="code-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className="code-dot" style={{ background: '#EF4444' }} />
                <span className="code-dot" style={{ background: '#F59E0B' }} />
                <span className="code-dot" style={{ background: '#10B981' }} />
                <span style={{ marginLeft: '8px' }}>安全代码 · {safeCode.length} 段参考</span>
              </div>
              <button
                onClick={handleCopyCode}
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '6px',
                  borderRadius: '8px',
                  padding: '4px 10px',
                  fontSize: '12px',
                  fontWeight: 500,
                  transition: 'all 0.2s',
                  background: codeCopied ? 'rgba(16,185,129,0.15)' : 'rgba(255,255,255,0.08)',
                  color: codeCopied ? '#10B981' : 'rgba(255,255,255,0.7)',
                  border: codeCopied ? '1px solid rgba(16,185,129,0.3)' : '1px solid rgba(255,255,255,0.1)',
                  cursor: 'pointer',
                }}
                title="复制代码"
              >
                {codeCopied ? (
                  <>
                    <Check size={12} />
                    已复制
                  </>
                ) : (
                  <>
                    <Copy size={12} />
                    复制代码
                  </>
                )}
              </button>
            </div>
            <pre className="custom-scrollbar" style={{ margin: 0 }}>
              {safeCode.map((item, idx) => (
                <div key={idx} style={{ marginBottom: idx < safeCode.length - 1 ? '16px' : '0' }}>
                  <span style={{ color: '#5EEAD4', opacity: 0.7 }}>{'// '}{item.location}</span>
                  {'\n'}
                  <span style={{ color: '#E2E8F0' }}>{item.description}</span>
                </div>
              ))}
            </pre>
          </div>
        </div>
      )}

      {/* ATT&CK Heatmap */}
      <div className="animate-slide-up" style={{ marginBottom: '24px', animationDelay: '300ms', animationFillMode: 'both' }}>
        {heatmapTechniques.length > 0 ? (
          <ATTACKHeatmap techniques={heatmapTechniques} />
        ) : (
          <div
            style={{
              borderRadius: '16px',
              border: '1px solid var(--border-light)',
              background: 'var(--bg-card)',
              padding: '24px',
              boxShadow: 'var(--shadow-sm)',
            }}
          >
            <h2
              style={{ marginBottom: '12px', fontWeight: 600, fontSize: '18px', color: 'var(--text-primary)' }}
            >
              ATT&CK 热力图
            </h2>
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '12px',
                borderRadius: '12px',
                padding: '16px',
                background: 'rgba(148,163,184,0.04)',
              }}
            >
              <Shield size={20} style={{ color: 'var(--text-muted)' }} />
              <span style={{ fontSize: '14px', color: 'var(--text-secondary)' }}>
                未检测到 ATT&CK 技术映射
              </span>
            </div>
          </div>
        )}
      </div>

      {/* Visualization Charts */}
      <div
        className="animate-slide-up"
        style={{ marginBottom: '24px', animationDelay: '330ms', animationFillMode: 'both' }}
      >
        <h2
          style={{ marginBottom: '16px', fontWeight: 600, fontSize: '18px', color: 'var(--text-primary)' }}
        >
          安全可视化
        </h2>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '16px' }}>
          {/* Severity Bar Chart */}
          <SeverityBarChart data={(() => {
            const sevColorMap: Record<string, string> = { high: '#EF4444', medium: '#F59E0B', low: '#10B981', info: '#94A3B8' }
            const sevLabelMap: Record<string, string> = { high: '高危', medium: '中危', low: '低危', info: '信息' }
            return Object.entries(severityCounts)
              .filter(([key]) => key !== 'all' && severityCounts[key] > 0)
              .map(([key, count]) => ({ name: sevLabelMap[key] ?? key, count, fill: sevColorMap[key] ?? '#94A3B8' }))
          })()} />
          {/* Vulnerability Type Donut */}
          <VulnTypeDonutChart data={(() => {
            const typeCounts: Record<string, { count: number; color: string }> = {}
            const cweColorMap: Record<string, string> = {
              'CWE-89': '#EF4444', 'CWE-79': '#5BA3FF', 'CWE-78': '#F59E0B',
              'CWE-22': '#5EEAD4', 'CWE-798': '#10B981', 'CWE-352': '#94A3B8',
              'CWE-200': '#8B5CF6', 'CWE-611': '#EC4899', 'CWE-502': '#F97316', 'CWE-918': '#06B6D4',
            }
            const cweLabelMap: Record<string, string> = {
              'CWE-89': 'SQL 注入', 'CWE-79': 'XSS', 'CWE-78': '命令注入',
              'CWE-22': '路径遍历', 'CWE-798': '硬编码密钥', 'CWE-352': 'CSRF',
              'CWE-200': '信息泄露', 'CWE-611': 'XXE', 'CWE-502': '反序列化', 'CWE-918': 'SSRF',
            }
            vulnerabilities.forEach((v) => {
              const cwe = v.cwe || '其他'
              if (!typeCounts[cwe]) {
                typeCounts[cwe] = { count: 0, color: cweColorMap[cwe] || '#94A3B8' }
              }
              typeCounts[cwe].count++
            })
            return Object.entries(typeCounts).map(([cwe, info]) => ({
              name: cweLabelMap[cwe] || cwe,
              value: info.count,
              color: info.color,
            }))
          })()} />
          {/* Risk Radar */}
          <RiskRadarChart data={[]} />
        </div>
      </div>

      {/* Interactive Chat Panel */}
      <div
        className="animate-slide-up"
        style={{
          borderRadius: '16px',
          border: '1px solid var(--border-light)',
          background: 'var(--bg-card)',
          overflow: 'hidden',
          boxShadow: 'var(--shadow-sm)',
          animationDelay: '360ms',
          animationFillMode: 'both',
        }}
      >
        {/* Chat Header */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            borderBottom: '1px solid var(--border-light)',
            padding: '16px 24px',
          }}
        >
          <MessageSquare size={16} style={{ color: 'var(--accent-start)' }} />
          <h3 style={{ fontWeight: 600, fontSize: '16px', color: 'var(--text-primary)' }}>
            交互式追问
          </h3>
          <span
            style={{
              marginLeft: '8px',
              borderRadius: '8px',
              padding: '2px 8px',
              fontSize: '10px',
              fontWeight: 500,
              background: 'rgba(91,163,255,0.06)',
              color: 'var(--accent-start)',
            }}
          >
            AI 驱动
          </span>
        </div>

        {/* Chat Messages */}
        <div
          className="custom-scrollbar"
          style={{ maxHeight: '320px', overflowY: 'auto', padding: '16px 24px' }}
        >
          {messages.length === 0 && !isChatTyping && (
            <div
              style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '32px 0', color: 'var(--text-muted)' }}
            >
              <p style={{ fontSize: '14px' }}>向 AI 助手提问关于分析结果的问题</p>
            </div>
          )}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            {messages.map((msg) => (
              <div
                key={msg.id}
                style={{ display: 'flex', justifyContent: msg.role === 'user' ? 'flex-end' : 'flex-start' }}
              >
                <div
                  style={{
                    maxWidth: '80%',
                    borderRadius: '16px',
                    padding: '12px 16px',
                    background:
                      msg.role === 'user'
                        ? 'var(--accent-gradient)'
                        : 'rgba(148,163,184,0.04)',
                    color:
                      msg.role === 'user' ? 'white' : 'var(--text-primary)',
                  }}
                >
                  <div
                    style={{ fontSize: '14px', lineHeight: 1.6, whiteSpace: 'pre-wrap' }}
                  >
                    {msg.content}
                  </div>
                  <div
                    style={{ marginTop: '6px', fontSize: '10px', textAlign: 'right', color: msg.role === 'user' ? 'rgba(255,255,255,0.6)' : 'var(--text-muted)' }}
                  >
                    {msg.time}
                  </div>
                </div>
              </div>
            ))}
            {isChatTyping && (
              <div style={{ display: 'flex', justifyContent: 'flex-start' }}>
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px',
                    borderRadius: '16px',
                    padding: '14px 20px',
                    background: 'rgba(148,163,184,0.04)',
                  }}
                >
                  <span className="typing-dot" />
                  <span className="typing-dot" />
                  <span className="typing-dot" />
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Chat Error */}
        {chatError && (
          <div
            style={{
              margin: '0 24px 8px',
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              borderRadius: '12px',
              padding: '8px 16px',
              background: 'rgba(239,68,68,0.06)',
              border: '1px solid rgba(239,68,68,0.15)',
            }}
          >
            <AlertCircle size={14} style={{ color: '#EF4444', flexShrink: 0 }} />
            <span style={{ fontSize: '12px', color: '#EF4444' }}>{chatError}</span>
          </div>
        )}

        {/* Chat Input */}
        <div
          style={{ borderTop: '1px solid var(--border-light)', padding: '16px 24px' }}
        >
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '12px',
              borderRadius: '12px',
              border: '1px solid var(--border-normal)',
              padding: '8px 16px',
              transition: 'border-color 0.15s',
            }}
            onFocus={(e) => {
              e.currentTarget.style.borderColor = 'var(--border-focus)'
            }}
            onBlur={(e) => {
              e.currentTarget.style.borderColor = 'var(--border-normal)'
            }}
          >
            <input
              type="text"
              value={chatInput}
              onChange={(e) => {
                setChatInput(e.target.value)
                if (chatError) setChatError(null)
              }}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                  e.preventDefault()
                  handleSendMessage()
                }
              }}
              placeholder="追问关于分析结果的问题..."
              style={{
                flex: 1,
                background: 'transparent',
                fontSize: '14px',
                border: 'none',
                outline: 'none',
                color: 'var(--text-primary)',
              }}
              disabled={isChatTyping}
            />
            <button
              onClick={handleSendMessage}
              disabled={!chatInput.trim() || isChatTyping}
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                borderRadius: '8px',
                padding: '8px',
                border: 'none',
                background: 'transparent',
                color: 'var(--accent-start)',
                cursor: chatInput.trim() && !isChatTyping ? 'pointer' : 'not-allowed',
                opacity: chatInput.trim() && !isChatTyping ? 1 : 0.4,
                transition: 'background 0.15s',
              }}
              onMouseEnter={(e) => {
                if (chatInput.trim()) e.currentTarget.style.background = 'rgba(91,163,255,0.06)'
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.background = 'transparent'
              }}
            >
              <Send size={16} />
            </button>
          </div>
          <div
            style={{ marginTop: '8px', fontSize: '10px', color: 'var(--text-muted)' }}
          >
            按 Enter 发送，Shift+Enter 换行
          </div>
        </div>
      </div>

      {/* CWE Detail Modal */}
      <CWEDetailModal
        cweId={selectedCweId}
        open={cweModalOpen}
        onCancel={() => setCweModalOpen(false)}
      />
    </div>
  )
}

export default Report
