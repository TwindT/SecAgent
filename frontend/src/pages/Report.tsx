import { useState, useEffect, useMemo, useCallback, useRef } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { Modal, Spin, message, Table, Tabs, Tag, Progress, Tooltip } from 'antd'
import type { ColumnsType } from 'antd/es/table'
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
  Globe,
  Hash,
  Link2,
  MapPin,
  Skull,
  Eye,
  ShieldAlert,
  Terminal,
  Activity,
  Search,
  FileCode,
  Bot,
  User,
} from 'lucide-react'
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter'
import { oneDark } from 'react-syntax-highlighter/dist/esm/styles/prism'
import { marked } from 'marked'
import {
  RiskRadarChart,
  VulnTypeDonutChart,
  SeverityBarChart,
} from '../components/secagent/VisualizationCharts'
import ATTACKHeatmap, { type ATTCKTechnique } from '../components/secagent/ATTACKHeatmap'
import { getTask, sendMessage, getConversations, downloadPdfReport, downloadMdReport, type TaskResponse, type ConversationResponse } from '../services/api'

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

function RiskLevelBadge({ level, large }: { level: string; large?: boolean }) {
  const config: Record<string, { label: string; color: string; bg: string; borderColor: string; icon: React.ComponentType<{ size?: number }> }> = {
    high: { label: '高危', color: '#EF4444', bg: 'rgba(239,68,68,0.12)', borderColor: 'rgba(239,68,68,0.3)', icon: AlertTriangle },
    medium: { label: '中危', color: '#F59E0B', bg: 'rgba(245,158,11,0.12)', borderColor: 'rgba(245,158,11,0.3)', icon: Zap },
    low: { label: '低危', color: '#10B981', bg: 'rgba(16,185,129,0.12)', borderColor: 'rgba(16,185,129,0.3)', icon: ShieldCheck },
    info: { label: '信息', color: '#94A3B8', bg: 'rgba(148,163,184,0.12)', borderColor: 'rgba(148,163,184,0.3)', icon: InfoIcon },
  }
  const c = config[level] || config.info
  const Icon = c.icon
  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: large ? '10px' : '8px',
        borderRadius: large ? '16px' : '12px',
        padding: large ? '10px 20px' : '8px 16px',
        fontSize: large ? '16px' : '14px',
        fontWeight: 700,
        background: c.bg,
        color: c.color,
        border: `1px solid ${c.borderColor}`,
        boxShadow: large ? `0 0 12px ${c.bg}` : 'none',
      }}
    >
      <Icon size={large ? 20 : 16} />
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

// ─── Malware Analysis Types (5.1-4) ────────────────
interface ParsedVerdict {
  maliciousness: string // 'malicious' | 'suspicious' | 'safe'
  confidence: string    // 'high' | 'medium' | 'low'
  reason: string
}

interface ParsedBehavior {
  id: number
  description: string
  severity: string
  evidence: string
  attack_technique: string
  attack_tactic: string
}

interface ParsedIOC {
  type: string
  value: string
  context: string
  threat_intel_result: string
  threat_intel_detail: string
}

interface ParsedYaraMatch {
  rule_name: string
  description: string
}

interface ParsedMalwareResult {
  analysis_type: string
  verdict: ParsedVerdict
  behaviors: ParsedBehavior[]
  iocs: ParsedIOC[]
  attack_matrix: Array<{ technique_id: string; technique_name: string; tactic: string }>
  yara_matches: ParsedYaraMatch[]
  overall_assessment: string
  recommendations: string[]
}

interface ParsedResult {
  THOUGHT?: string
  VULNERABILITIES?: ParsedVulnerability[]
  SAFE_CODE?: string | Array<{ location: string; description: string }>
  ATTACK_TECHNIQUES?: ParsedAttackTechnique[]
  SUMMARY?: string
  rawAnalysis?: string
  // Malware analysis fields
  analysis_type?: string
  verdict?: ParsedVerdict
  behaviors?: ParsedBehavior[]
  iocs?: ParsedIOC[]
  attack_matrix?: Array<{ technique_id: string; technique_name: string; tactic: string }>
  yara_matches?: ParsedYaraMatch[]
  overall_assessment?: string
  recommendations?: string[]
}

interface ChatMessage {
  id: string
  role: 'user' | 'assistant'
  content: string
  time: string
}

// ─── Vulnerability Table Row Type ───────────────────
interface VulnerabilityRow {
  key: string
  index: number
  title: string
  severity: string
  cwe: string
  location: string
  description: string
  codeSnippet: string
  fixSuggestion: string
}

// ─── IOC Table Row Type ─────────────────────────────
interface IOCRow {
  key: string
  index: number
  type: string
  value: string
  context: string
  threatIntelResult: string
  threatIntelDetail: string
}

// ─── Task type display labels ────────────────────────
const taskTypeLabels: Record<string, string> = {
  vulnerability_detection: '代码漏洞检测',
  malware_analysis: '恶意代码分析',
}

// ─── Severity filter options ─────────────────────────
const severityFilterOptions = [
  { key: 'all', label: '全部' },
  { key: 'high', label: '高危' },
  { key: 'medium', label: '中危' },
  { key: 'low', label: '低危' },
  { key: 'info', label: '信息' },
] as const

// ─── Detect code language from snippet ──────────────
function detectLanguage(code: string): string {
  if (!code) return 'text'
  const trimmed = code.trim()
  // Python patterns
  if (/^\s*(def |class |import |from |if __name__|print\(|self\.)/m.test(trimmed)) return 'python'
  // Java patterns
  if (/^\s*(public\s+class|private\s+|protected\s+|System\.out|import\s+java\.)/m.test(trimmed)) return 'java'
  // JavaScript/TypeScript patterns
  if (/^\s*(const\s|let\s|var\s|function\s|=>|require\(|module\.exports)/m.test(trimmed)) return 'javascript'
  // C/C++ patterns
  if (/^\s*#\s*include|int\s+main|printf\s*\(/m.test(trimmed)) return 'cpp'
  // Go patterns
  if (/^\s*(package\s+|func\s+|fmt\.|go\s)/m.test(trimmed)) return 'go'
  // Rust patterns
  if (/^\s*(fn\s+|let\s+mut|pub\s+fn|impl\s+)/m.test(trimmed)) return 'rust'
  // PHP patterns
  if (/^\s*<\?php|\$\w+/m.test(trimmed)) return 'php'
  // SQL patterns
  if (/^\s*(SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP)\s/im.test(trimmed)) return 'sql'
  // Shell/Bash patterns
  if (/^\s*(#!\/bin\/|echo\s|export\s|chmod\s)/m.test(trimmed)) return 'bash'
  return 'text'
}

// ─── IOC type icon helper ───────────────────────────
function IOCTypeIcon({ type }: { type: string }) {
  const t = (type || '').toLowerCase()
  if (t.includes('ip') || t.includes('ipv4') || t.includes('ipv6')) {
    return <Globe size={14} style={{ color: 'var(--accent-start)' }} />
  }
  if (t.includes('domain') || t.includes('dns')) {
    return <Link2 size={14} style={{ color: '#10B981' }} />
  }
  if (t.includes('url') || t.includes('uri')) {
    return <ExternalLink size={14} style={{ color: '#F59E0B' }} />
  }
  if (t.includes('hash') || t.includes('md5') || t.includes('sha') || t.includes('crc')) {
    return <Hash size={14} style={{ color: '#8B5CF6' }} />
  }
  if (t.includes('email') || t.includes('mail')) {
    return <MessageSquare size={14} style={{ color: '#EC4899' }} />
  }
  if (t.includes('file') || t.includes('path')) {
    return <FileCode size={14} style={{ color: '#06B6D4' }} />
  }
  return <Search size={14} style={{ color: 'var(--text-muted)' }} />
}

// ─── Tactic name mapping ────────────────────────────
const tacticNameMap: Record<string, string> = {
  initial_access: '初始访问',
  execution: '执行',
  persistence: '持久化',
  privilege_escalation: '权限提升',
  defense_evasion: '防御规避',
  credential_access: '凭证访问',
  discovery: '发现',
  lateral_movement: '横向移动',
  collection: '收集',
  exfiltration: '数据渗出',
  command_and_control: '命令控制',
}

// ─── Main Component ─────────────────────────────────
const Report = () => {
  const { taskId } = useParams<{ taskId: string }>()
  const navigate = useNavigate()

  // Configure marked for safe chat rendering
  useMemo(() => {
    marked.setOptions({ breaks: true, gfm: true })
  }, [])

  // ─── API state ───────────────────────────────────
  const [task, setTask] = useState<TaskResponse | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // ─── UI state ────────────────────────────────────
  const [expandedVulns, setExpandedVulns] = useState<Set<string>>(new Set())
  const [chatInput, setChatInput] = useState('')
  const [messages, setMessages] = useState<ChatMessage[]>([])
  const [isChatTyping, setIsChatTyping] = useState(false)
  const [isWaitingResponse, setIsWaitingResponse] = useState(false)
  const [chatError, setChatError] = useState<string | null>(null)
  const chatMessagesRef = useRef<HTMLDivElement>(null)
  const chatInputRef = useRef<HTMLTextAreaElement>(null)

  // ─── Enhancement state ───────────────────────────
  const [cweModalOpen, setCweModalOpen] = useState(false)
  const [selectedCweId, setSelectedCweId] = useState<string | null>(null)
  const [codeCopied, setCodeCopied] = useState(false)
  const [severityFilter, setSeverityFilter] = useState<string>('all')

  // ─── 5.1-7: Markdown preview state ───────────────
  const [markdownContent, setMarkdownContent] = useState<string>('')
  const [markdownLoading, setMarkdownLoading] = useState(false)

  // ─── 5.1-8: PDF download progress state ─────────
  const [pdfDownloading, setPdfDownloading] = useState(false)
  const [pdfProgress, setPdfProgress] = useState(0)

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

        // Load conversation history from dedicated API
        try {
          const convRes = await getConversations(Number(taskId))
          if (convRes.data && convRes.data.length > 0) {
            setMessages(
              convRes.data.map((c: ConversationResponse) => ({
                id: String(c.id),
                role: c.role,
                content: c.content,
                time: new Date(c.created_at).toLocaleTimeString('zh-CN', {
                  hour: '2-digit',
                  minute: '2-digit',
                }),
              }))
            )
          }
        } catch {
          // 对话历史加载失败不影响主报告展示
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : '加载报告失败')
      } finally {
        setIsLoading(false)
      }
    }
    loadTask()
  }, [taskId])

  // ─── Auto-scroll chat to bottom ──────────────────
  useEffect(() => {
    if (chatMessagesRef.current) {
      chatMessagesRef.current.scrollTop = chatMessagesRef.current.scrollHeight
    }
  }, [messages, isChatTyping, isWaitingResponse])

  // ─── Parse resultJson ────────────────────────────
  const resultData = useMemo<ParsedResult | null>(() => {
    if (!task?.result_json) return null
    try {
      return JSON.parse(task.result_json) as ParsedResult
    } catch {
      return null
    }
  }, [task?.result_json])

  // ─── Is malware analysis? ────────────────────────
  const isMalwareAnalysis = useMemo(() => {
    if (task?.type === 'malware_analysis') return true
    if (resultData?.analysis_type === 'malware_analysis') return true
    if (resultData?.verdict) return true
    return false
  }, [task?.type, resultData])

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

  // ─── 5.1-4: Malware analysis parsed data ─────────
  const malwareResult = useMemo<ParsedMalwareResult | null>(() => {
    if (!resultData) return null
    if (!resultData.verdict && !resultData.analysis_type && !isMalwareAnalysis) return null
    return {
      analysis_type: resultData.analysis_type || 'malware_analysis',
      verdict: resultData.verdict || { maliciousness: 'safe', confidence: 'low', reason: '' },
      behaviors: resultData.behaviors || [],
      iocs: resultData.iocs || [],
      attack_matrix: resultData.attack_matrix || [],
      yara_matches: resultData.yara_matches || [],
      overall_assessment: resultData.overall_assessment || '',
      recommendations: resultData.recommendations || [],
    }
  }, [resultData, isMalwareAnalysis])

  // ─── 5.1-5: IOC data ─────────────────────────────
  const iocData = useMemo<IOCRow[]>(() => {
    const iocs = malwareResult?.iocs || (resultData as any)?.iocs || []
    return iocs.map((ioc: ParsedIOC, idx: number) => ({
      key: `ioc-${idx}`,
      index: idx + 1,
      type: ioc.type || '未知',
      value: ioc.value || '--',
      context: ioc.context || '--',
      threatIntelResult: ioc.threat_intel_result || 'unknown',
      threatIntelDetail: ioc.threat_intel_detail || '',
    }))
  }, [malwareResult, resultData])

  // Map ParsedAttackTechnique[] to ATTCKTechnique[] for heatmap
  const heatmapTechniques = useMemo<ATTCKTechnique[]>(() => {
    const techs: ATTCKTechnique[] = []
    // From ATTACK_TECHNIQUES
    for (const tech of attckTechniques) {
      techs.push({
        id: tech.id,
        name: tech.name,
        tactic: tech.tactic,
        confidence: 70,
      })
    }
    // From malware attack_matrix
    if (malwareResult?.attack_matrix) {
      for (const tech of malwareResult.attack_matrix) {
        if (!techs.find(t => t.id === tech.technique_id)) {
          techs.push({
            id: tech.technique_id,
            name: tech.technique_name,
            tactic: tech.tactic,
            confidence: 70,
          })
        }
      }
    }
    return techs
  }, [attckTechniques, malwareResult])

  // ─── 5.1-6: All ATT&CK techniques for Tag display ──
  const allAttackTechniques = useMemo(() => {
    const techs: Array<{ id: string; name: string; tactic: string }> = []
    for (const tech of attckTechniques) {
      techs.push({ id: tech.id, name: tech.name, tactic: tech.tactic })
    }
    if (malwareResult?.attack_matrix) {
      for (const tech of malwareResult.attack_matrix) {
        if (!techs.find(t => t.id === tech.technique_id)) {
          techs.push({ id: tech.technique_id, name: tech.technique_name, tactic: tech.tactic })
        }
      }
    }
    return techs
  }, [attckTechniques, malwareResult])

  const summary = useMemo(() => {
    if (!resultData) return null
    return resultData.SUMMARY || resultData.rawAnalysis || malwareResult?.overall_assessment || null
  }, [resultData, malwareResult])

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

  // ─── 5.1-1: Target file/code name ────────────────
  const targetName = useMemo(() => {
    if (task?.input_path) {
      // Extract filename from path
      const parts = task.input_path.replace(/\\/g, '/').split('/')
      return parts[parts.length - 1] || task.input_path
    }
    if (task?.input_content) {
      // Truncate input_content for display
      const content = task.input_content.trim()
      if (content.length > 60) {
        return content.substring(0, 60) + '...'
      }
      return content
    }
    return '--'
  }, [task])

  // ─── Filtered vulnerabilities ────────────────────
  const filteredVulnerabilities = useMemo(() => {
    if (severityFilter === 'all') return vulnerabilities
    return vulnerabilities.filter((v) => (v.severity || 'info') === severityFilter)
  }, [vulnerabilities, severityFilter])

  // ─── Vulnerability table rows ────────────────────
  const vulnTableRows = useMemo<VulnerabilityRow[]>(() => {
    return filteredVulnerabilities.map((vuln, idx) => {
      const originalIdx = vulnerabilities.indexOf(vuln)
      return {
        key: `VULN-${String(originalIdx + 1).padStart(3, '0')}`,
        index: originalIdx + 1,
        title: vuln.title,
        severity: vuln.severity || 'info',
        cwe: vuln.cwe || '',
        location: vuln.location || '--',
        description: vuln.description,
        codeSnippet: vuln.codeSnippet || '',
        fixSuggestion: vuln.fixSuggestion || '',
      }
    })
  }, [filteredVulnerabilities, vulnerabilities])

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
    filteredVulnerabilities.every((_, idx) => expandedVulns.has(`VULN-${String(vulnerabilities.indexOf(filteredVulnerabilities[idx]) + 1).padStart(3, '0')}`))

  const toggleAllVulns = () => {
    if (allExpanded) {
      setExpandedVulns(new Set())
    } else {
      const newSet = new Set<string>()
      filteredVulnerabilities.forEach((vuln) => {
        const originalIdx = vulnerabilities.indexOf(vuln)
        newSet.add(`VULN-${String(originalIdx + 1).padStart(3, '0')}`)
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

  // ─── 5.1-8: Export handler with progress ─────────
  const handleExport = () => {
    if (!taskId) {
      message.error('导出失败：未选择分析任务')
      return
    }
    setPdfDownloading(true)
    setPdfProgress(0)

    // Simulate progress before actual download
    const progressTimer = setInterval(() => {
      setPdfProgress(prev => {
        if (prev >= 90) {
          clearInterval(progressTimer)
          return 90
        }
        return prev + 10
      })
    }, 300)

    downloadPdfReport(Number(taskId)).then((res) => {
      clearInterval(progressTimer)
      setPdfProgress(100)
      const url = window.URL.createObjectURL(new Blob([res.data]))
      const link = document.createElement('a')
      link.href = url
      link.setAttribute('download', `report_${taskId}.pdf`)
      document.body.appendChild(link)
      link.click()
      link.remove()
      window.URL.revokeObjectURL(url)
      message.success('PDF 报告下载完成')
      setTimeout(() => {
        setPdfDownloading(false)
        setPdfProgress(0)
      }, 1500)
    }).catch(() => {
      clearInterval(progressTimer)
      message.error('导出失败，请稍后重试')
      setPdfDownloading(false)
      setPdfProgress(0)
    })
  }

  // ─── 5.1-7: Load markdown content ────────────────
  const loadMarkdownContent = useCallback(async () => {
    if (!taskId || markdownContent) return
    setMarkdownLoading(true)
    try {
      const res = await downloadMdReport(Number(taskId))
      setMarkdownContent(res.data || '')
    } catch {
      message.error('加载 Markdown 报告失败')
    } finally {
      setMarkdownLoading(false)
    }
  }, [taskId, markdownContent])

  // ─── Chat handler ────────────────────────────────
  const handleSendMessage = async () => {
    if (!chatInput.trim() || isChatTyping || isWaitingResponse || !taskId) return

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
    const inputText = chatInput
    setChatInput('')
    setIsWaitingResponse(true)
    setChatError(null)

    try {
      const res = await sendMessage(Number(taskId), { message: inputText })
      const fullReply = res.data.reply
      setIsWaitingResponse(false)
      setIsChatTyping(true)

      // Typing animation: gradually reveal the reply
      const agentMsgId = `${Date.now() + 1}`
      const agentTime = new Date().toLocaleTimeString('zh-CN', {
        hour: '2-digit',
        minute: '2-digit',
      })

      // Add empty agent message first
      setMessages((prev) => [
        ...prev,
        { id: agentMsgId, role: 'assistant', content: '', time: agentTime },
      ])

      // Animate character by character
      const charsPerTick = 3
      const tickInterval = 20
      let currentIndex = 0

      await new Promise<void>((resolve) => {
        const timer = setInterval(() => {
          currentIndex += charsPerTick
          if (currentIndex >= fullReply.length) {
            currentIndex = fullReply.length
            clearInterval(timer)
            resolve()
          }
          setMessages((prev) =>
            prev.map((m) =>
              m.id === agentMsgId
                ? { ...m, content: fullReply.slice(0, currentIndex) }
                : m
            )
          )
        }, tickInterval)
      })
    } catch (err) {
      setChatError(err instanceof Error ? err.message : '发送失败，请重试')
      message.error('发送失败，请稍后重试')
      setIsWaitingResponse(false)
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

  // ─── 5.1-2: Vulnerability Table columns ──────────
  const vulnColumns: ColumnsType<VulnerabilityRow> = useMemo(() => [
    {
      title: '编号',
      dataIndex: 'index',
      key: 'index',
      width: 70,
      align: 'center' as const,
      render: (val: number) => (
        <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)' }}>
          #{String(val).padStart(3, '0')}
        </span>
      ),
    },
    {
      title: '漏洞标题',
      dataIndex: 'title',
      key: 'title',
      ellipsis: true,
      render: (text: string) => (
        <span style={{ fontWeight: 500, fontSize: '14px', color: 'var(--text-primary)' }}>{text}</span>
      ),
    },
    {
      title: '严重等级',
      dataIndex: 'severity',
      key: 'severity',
      width: 100,
      align: 'center' as const,
      render: (sev: string) => {
        const color = severityColors[sev] || '#94A3B8'
        const bg = severityBgColors[sev] || 'rgba(148,163,184,0.06)'
        return (
          <Tag
            color={color}
            style={{
              margin: 0,
              borderRadius: '8px',
              fontSize: '12px',
              fontWeight: 600,
              border: 'none',
              background: bg,
            }}
          >
            {severityLabels[sev] || '信息'}
          </Tag>
        )
      },
    },
    {
      title: 'CWE',
      dataIndex: 'cwe',
      key: 'cwe',
      width: 120,
      align: 'center' as const,
      render: (cwe: string) => {
        if (!cwe) return <span style={{ color: 'var(--text-muted)' }}>--</span>
        return (
          <button
            onClick={() => handleOpenCweModal(cwe)}
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
            {cwe}
            <ExternalLink size={10} />
          </button>
        )
      },
    },
    {
      title: '位置',
      dataIndex: 'location',
      key: 'location',
      width: 200,
      ellipsis: true,
      render: (text: string) => (
        <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>{text}</span>
      ),
    },
  ], [])

  // ─── 5.1-5: IOC Table columns ────────────────────
  const iocColumns: ColumnsType<IOCRow> = useMemo(() => [
    {
      title: '#',
      dataIndex: 'index',
      key: 'index',
      width: 50,
      align: 'center' as const,
      render: (val: number) => (
        <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>{val}</span>
      ),
    },
    {
      title: '类型',
      dataIndex: 'type',
      key: 'type',
      width: 100,
      align: 'center' as const,
      render: (type: string) => (
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', fontSize: '12px', color: 'var(--text-primary)' }}>
          <IOCTypeIcon type={type} />
          {type}
        </span>
      ),
    },
    {
      title: 'IOC 值',
      dataIndex: 'value',
      key: 'value',
      ellipsis: true,
      render: (val: string) => (
        <code style={{
          fontSize: '12px',
          fontFamily: "'JetBrains Mono', 'Fira Code', Consolas, monospace",
          color: 'var(--accent-start)',
          background: 'rgba(91,163,255,0.06)',
          padding: '2px 6px',
          borderRadius: '4px',
        }}>
          {val}
        </code>
      ),
    },
    {
      title: '上下文',
      dataIndex: 'context',
      key: 'context',
      width: 200,
      ellipsis: true,
      render: (text: string) => (
        <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>{text}</span>
      ),
    },
    {
      title: '威胁情报',
      dataIndex: 'threatIntelResult',
      key: 'threatIntelResult',
      width: 120,
      align: 'center' as const,
      render: (result: string, record: IOCRow) => {
        const r = (result || 'unknown').toLowerCase()
        if (r.includes('malicious') || r.includes('known') || r.includes('恶意') || r === 'malicious') {
          return (
            <Tooltip title={record.threatIntelDetail || '已知恶意指标'}>
              <Tag color="#EF4444" style={{ margin: 0, borderRadius: '8px', fontSize: '12px', fontWeight: 600, border: 'none' }}>
                已知恶意
              </Tag>
            </Tooltip>
          )
        }
        if (r.includes('suspicious') || r.includes('可疑')) {
          return (
            <Tooltip title={record.threatIntelDetail || '可疑指标'}>
              <Tag color="#F59E0B" style={{ margin: 0, borderRadius: '8px', fontSize: '12px', fontWeight: 600, border: 'none' }}>
                可疑
              </Tag>
            </Tooltip>
          )
        }
        return (
          <Tooltip title={record.threatIntelDetail || '未在威胁情报库中找到'}>
            <Tag color="#94A3B8" style={{ margin: 0, borderRadius: '8px', fontSize: '12px', fontWeight: 600, border: 'none' }}>
              未知
            </Tag>
          </Tooltip>
        )
      },
    },
  ], [])

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

  // ─── Structured View Content ─────────────────────
  const structuredViewContent = (
    <>
      {/* ─── 5.1-1: Report Info Bar (Enhanced) ──────── */}
      <div
        className="animate-slide-up"
        style={{
          marginBottom: '24px',
          display: 'grid',
          gridTemplateColumns: 'repeat(5, 1fr)',
          gap: '16px',
          animationDelay: '60ms',
          animationFillMode: 'both',
        }}
      >
        {[
          { label: '目标文件', value: targetName, icon: FileCode },
          { label: '分析时间', value: analyzedAt, icon: Clock },
          { label: '分析耗时', value: duration, icon: Zap },
          { label: '风险等级', value: <RiskLevelBadge level={riskLevel} large />, icon: Shield },
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
                <div
                  style={{
                    fontSize: '14px',
                    fontWeight: 600,
                    color: 'var(--text-primary)',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                  }}
                  title={typeof item.value === 'string' ? item.value : undefined}
                >
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

      {/* ─── 5.1-4: Malware Analysis Result ──────────── */}
      {isMalwareAnalysis && malwareResult && (
        <div
          className="animate-slide-up"
          style={{
            marginBottom: '24px',
            borderRadius: '16px',
            border: '1px solid var(--border-light)',
            background: 'var(--bg-card)',
            overflow: 'hidden',
            boxShadow: 'var(--shadow-sm)',
            animationDelay: '150ms',
            animationFillMode: 'both',
          }}
        >
          {/* Verdict Header */}
          <div
            style={{
              padding: '24px',
              borderBottom: '1px solid var(--border-light)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              flexWrap: 'wrap' as const,
              gap: '16px',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
              <h2 style={{ fontWeight: 600, fontSize: '18px', color: 'var(--text-primary)' }}>
                恶意分析结果
              </h2>
              {/* Verdict Badge */}
              {(() => {
                const v = (malwareResult.verdict?.maliciousness || 'safe').toLowerCase()
                const verdictConfig: Record<string, { icon: React.ComponentType<{ size?: number }>; label: string; color: string; bg: string; borderColor: string }> = {
                  malicious: { icon: Skull, label: '恶意', color: '#EF4444', bg: 'rgba(239,68,68,0.12)', borderColor: 'rgba(239,68,68,0.3)' },
                  suspicious: { icon: Eye, label: '可疑', color: '#F59E0B', bg: 'rgba(245,158,11,0.12)', borderColor: 'rgba(245,158,11,0.3)' },
                  safe: { icon: ShieldCheck, label: '安全', color: '#10B981', bg: 'rgba(16,185,129,0.12)', borderColor: 'rgba(16,185,129,0.3)' },
                }
                const cfg = verdictConfig[v] || verdictConfig.safe
                const Icon = cfg.icon
                return (
                  <span
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '10px',
                      borderRadius: '16px',
                      padding: '10px 24px',
                      fontSize: '18px',
                      fontWeight: 700,
                      background: cfg.bg,
                      color: cfg.color,
                      border: `2px solid ${cfg.borderColor}`,
                      boxShadow: `0 0 20px ${cfg.bg}`,
                    }}
                  >
                    <Icon size={24} />
                    {cfg.label}
                  </span>
                )
              })()}
            </div>
            {/* Confidence Progress */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', minWidth: '200px' }}>
              <span style={{ fontSize: '12px', fontWeight: 500, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                置信度
              </span>
              <Progress
                percent={(() => {
                  const c = (malwareResult.verdict?.confidence || 'low').toLowerCase()
                  if (c === 'high') return 90
                  if (c === 'medium') return 60
                  return 30
                })()}
                strokeColor={(() => {
                  const v = (malwareResult.verdict?.maliciousness || 'safe').toLowerCase()
                  if (v === 'malicious') return '#EF4444'
                  if (v === 'suspicious') return '#F59E0B'
                  return '#10B981'
                })()}
                trailColor="rgba(148,163,184,0.1)"
                size="small"
                style={{ flex: 1 }}
              />
              <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)' }}>
                {(() => {
                  const c = (malwareResult.verdict?.confidence || 'low').toLowerCase()
                  if (c === 'high') return '高'
                  if (c === 'medium') return '中'
                  return '低'
                })()}
              </span>
            </div>
          </div>

          {/* Verdict Reason */}
          {malwareResult.verdict?.reason && (
            <div style={{ padding: '16px 24px', borderBottom: '1px solid var(--border-light)' }}>
              <div style={{ fontSize: '12px', fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.05em', color: 'var(--text-muted)', marginBottom: '8px' }}>
                判定理由
              </div>
              <p style={{ fontSize: '14px', lineHeight: 1.6, color: 'var(--text-primary)', margin: 0 }}>
                {malwareResult.verdict.reason}
              </p>
            </div>
          )}

          {/* Behaviors List */}
          {malwareResult.behaviors && malwareResult.behaviors.length > 0 && (
            <div style={{ padding: '16px 24px', borderBottom: '1px solid var(--border-light)' }}>
              <div style={{ fontSize: '12px', fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.05em', color: 'var(--text-muted)', marginBottom: '12px' }}>
                行为描述 ({malwareResult.behaviors.length})
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                {malwareResult.behaviors.map((behavior, idx) => {
                  const bSev = (behavior.severity || 'info').toLowerCase()
                  const sevColor = severityColors[bSev] || '#94A3B8'
                  const sevBg = severityBgColors[bSev] || 'rgba(148,163,184,0.06)'
                  return (
                    <div
                      key={behavior.id || idx}
                      style={{
                        borderRadius: '12px',
                        border: '1px solid var(--border-light)',
                        background: 'var(--bg-page)',
                        padding: '16px',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px', flexWrap: 'wrap' as const }}>
                        <span style={{ fontSize: '14px', fontWeight: 500, color: 'var(--text-primary)' }}>
                          {behavior.description}
                        </span>
                        <Tag
                          color={sevColor}
                          style={{ margin: 0, borderRadius: '8px', fontSize: '11px', fontWeight: 600, border: 'none', background: sevBg }}
                        >
                          {severityLabels[bSev] || '信息'}
                        </Tag>
                        {behavior.attack_technique && (
                          <Tag
                            style={{
                              margin: 0,
                              borderRadius: '8px',
                              fontSize: '11px',
                              fontWeight: 500,
                              border: '1px solid rgba(91,163,255,0.2)',
                              background: 'rgba(91,163,255,0.06)',
                              color: 'var(--accent-start)',
                            }}
                          >
                            {behavior.attack_technique}
                          </Tag>
                        )}
                      </div>
                      {behavior.evidence && (
                        <div style={{ marginBottom: behavior.attack_tactic ? '8px' : '0' }}>
                          <span style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-muted)' }}>证据: </span>
                          <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>{behavior.evidence}</span>
                        </div>
                      )}
                      {behavior.attack_tactic && (
                        <div>
                          <span style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-muted)' }}>战术: </span>
                          <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                            {tacticNameMap[behavior.attack_tactic] || behavior.attack_tactic}
                          </span>
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            </div>
          )}

          {/* YARA Matches */}
          {malwareResult.yara_matches && malwareResult.yara_matches.length > 0 && (
            <div style={{ padding: '16px 24px', borderBottom: '1px solid var(--border-light)' }}>
              <div style={{ fontSize: '12px', fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.05em', color: 'var(--text-muted)', marginBottom: '12px' }}>
                YARA 规则匹配 ({malwareResult.yara_matches.length})
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap' as const, gap: '8px' }}>
                {malwareResult.yara_matches.map((match, idx) => (
                  <Tooltip key={idx} title={match.description || '无描述'}>
                    <Tag
                      style={{
                        borderRadius: '8px',
                        fontSize: '12px',
                        fontWeight: 500,
                        border: '1px solid rgba(139,92,246,0.2)',
                        background: 'rgba(139,92,246,0.06)',
                        color: '#8B5CF6',
                        cursor: 'default',
                      }}
                    >
                      <Terminal size={10} style={{ marginRight: '4px', verticalAlign: 'middle' }} />
                      {match.rule_name}
                    </Tag>
                  </Tooltip>
                ))}
              </div>
            </div>
          )}

          {/* Overall Assessment */}
          {malwareResult.overall_assessment && (
            <div style={{ padding: '16px 24px', borderBottom: '1px solid var(--border-light)' }}>
              <div style={{ fontSize: '12px', fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.05em', color: 'var(--text-muted)', marginBottom: '8px' }}>
                综合评估
              </div>
              <p style={{ fontSize: '14px', lineHeight: 1.6, color: 'var(--text-primary)', margin: 0 }}>
                {malwareResult.overall_assessment}
              </p>
            </div>
          )}

          {/* Recommendations */}
          {malwareResult.recommendations && malwareResult.recommendations.length > 0 && (
            <div style={{ padding: '16px 24px' }}>
              <div style={{ fontSize: '12px', fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.05em', color: '#10B981', marginBottom: '12px' }}>
                处置建议
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {malwareResult.recommendations.map((rec, idx) => (
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
                    <ShieldCheck size={14} style={{ color: '#10B981', flexShrink: 0, marginTop: '3px' }} />
                    <span style={{ fontSize: '14px', color: 'var(--text-primary)' }}>{rec}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ─── 5.1-5: IOC Table ────────────────────────── */}
      {iocData.length > 0 && (
        <div
          className="animate-slide-up"
          style={{
            marginBottom: '24px',
            borderRadius: '16px',
            border: '1px solid var(--border-light)',
            background: 'var(--bg-card)',
            overflow: 'hidden',
            boxShadow: 'var(--shadow-sm)',
            animationDelay: '180ms',
            animationFillMode: 'both',
          }}
        >
          <div style={{ padding: '16px 24px', borderBottom: '1px solid var(--border-light)' }}>
            <h2 style={{ fontWeight: 600, fontSize: '18px', color: 'var(--text-primary)' }}>
              IOC 指标清单 ({iocData.length})
            </h2>
            <p style={{ marginTop: '4px', fontSize: '14px', color: 'var(--text-secondary)' }}>
              恶意行为关联的入侵指标
            </p>
          </div>
          <div style={{ padding: '0 16px 16px' }}>
            <Table
              dataSource={iocData}
              columns={iocColumns}
              size="small"
              pagination={iocData.length > 10 ? { pageSize: 10, size: 'small' } : false}
              style={{ background: 'transparent' }}
              className="dark-table"
            />
          </div>
        </div>
      )}

      {/* ─── 5.1-2 + 5.1-3: Vulnerabilities Table ───── */}
      <div
        className="animate-slide-up"
        style={{ marginBottom: '24px', animationDelay: '200ms', animationFillMode: 'both' }}
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

            {/* Vulnerability Table */}
            <div
              style={{
                borderRadius: '16px',
                border: '1px solid var(--border-light)',
                background: 'var(--bg-card)',
                overflow: 'hidden',
                boxShadow: 'var(--shadow-sm)',
              }}
            >
              <Table
                dataSource={vulnTableRows}
                columns={vulnColumns}
                size="small"
                pagination={vulnTableRows.length > 20 ? { pageSize: 20, size: 'small' } : false}
                expandable={{
                  expandedRowKeys: Array.from(expandedVulns),
                  onExpandedRowsChange: (keys) => {
                    setExpandedVulns(new Set(keys as string[]))
                  },
                  expandedRowRender: (record) => (
                    <div style={{ padding: '8px 0' }}>
                      {/* Description */}
                      <p style={{ marginBottom: '16px', fontSize: '14px', lineHeight: 1.6, color: 'var(--text-primary)' }}>
                        {record.description}
                      </p>

                      {/* Code Snippet with Syntax Highlighting */}
                      {record.codeSnippet && (
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
                            }}
                          >
                            <SyntaxHighlighter
                              language={detectLanguage(record.codeSnippet)}
                              style={oneDark}
                              customStyle={{
                                margin: 0,
                                padding: '16px',
                                fontSize: '12px',
                                lineHeight: 1.6,
                                background: 'rgba(239,68,68,0.02)',
                              }}
                            >
                              {record.codeSnippet}
                            </SyntaxHighlighter>
                          </div>
                        </div>
                      )}

                      {/* Fix Suggestion with Green Background */}
                      {record.fixSuggestion && (
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
                              border: '1px solid rgba(16,185,129,0.15)',
                              background: 'rgba(16,185,129,0.04)',
                            }}
                          >
                            <SyntaxHighlighter
                              language={detectLanguage(record.fixSuggestion)}
                              style={oneDark}
                              customStyle={{
                                margin: 0,
                                padding: '16px',
                                fontSize: '12px',
                                lineHeight: 1.6,
                                background: 'transparent',
                              }}
                            >
                              {record.fixSuggestion}
                            </SyntaxHighlighter>
                          </div>
                        </div>
                      )}
                    </div>
                  ),
                }}
                style={{ background: 'transparent' }}
                className="dark-table"
                locale={{ emptyText: (
                  <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '24px' }}>
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
                )}}
              />
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

      {/* ─── 5.1-6: ATT&CK Heatmap + Tag List ───────── */}
      <div className="animate-slide-up" style={{ marginBottom: '24px', animationDelay: '300ms', animationFillMode: 'both' }}>
        {heatmapTechniques.length > 0 ? (
          <>
            <ATTACKHeatmap techniques={heatmapTechniques} />

            {/* ATT&CK Tag List */}
            {allAttackTechniques.length > 0 && (
              <div
                style={{
                  marginTop: '16px',
                  borderRadius: '16px',
                  border: '1px solid var(--border-light)',
                  background: 'var(--bg-card)',
                  padding: '20px 24px',
                  boxShadow: 'var(--shadow-sm)',
                }}
              >
                <h3 style={{ marginBottom: '12px', fontWeight: 600, fontSize: '16px', color: 'var(--text-primary)' }}>
                  ATT&CK 技术映射
                </h3>
                <div style={{ display: 'flex', flexWrap: 'wrap' as const, gap: '10px' }}>
                  {allAttackTechniques.map((tech, idx) => {
                    const tacticCn = tacticNameMap[tech.tactic] || tech.tactic
                    return (
                      <Tooltip
                        key={`${tech.id}-${idx}`}
                        title={`战术: ${tacticCn}`}
                      >
                        <Tag
                          style={{
                            margin: 0,
                            borderRadius: '10px',
                            padding: '6px 12px',
                            fontSize: '12px',
                            fontWeight: 500,
                            border: '1px solid rgba(91,163,255,0.2)',
                            background: 'rgba(91,163,255,0.06)',
                            color: 'var(--accent-start)',
                            cursor: 'default',
                            display: 'inline-flex',
                            flexDirection: 'column',
                            alignItems: 'flex-start',
                            gap: '2px',
                          }}
                        >
                          <span style={{ fontWeight: 600 }}>
                            {tech.id} - {tech.name}
                          </span>
                          <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontWeight: 400 }}>
                            {tacticCn}
                          </span>
                        </Tag>
                      </Tooltip>
                    )
                  })}
                </div>
              </div>
            )}
          </>
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
          {messages.length > 0 && (
            <span
              style={{
                marginLeft: 'auto',
                fontSize: '11px',
                color: 'var(--text-muted)',
              }}
            >
              {messages.length} 条对话
            </span>
          )}
        </div>

        {/* Chat Messages */}
        <div
          ref={chatMessagesRef}
          className="custom-scrollbar"
          style={{ maxHeight: '400px', overflowY: 'auto', padding: '16px 24px' }}
        >
          {messages.length === 0 && !isChatTyping && !isWaitingResponse && (
            <div
              style={{
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                justifyContent: 'center',
                padding: '40px 0',
                color: 'var(--text-muted)',
                gap: '12px',
              }}
            >
              <Bot size={32} style={{ opacity: 0.3 }} />
              <p style={{ fontSize: '14px' }}>向 AI 助手提问关于分析结果的问题</p>
              <p style={{ fontSize: '12px', opacity: 0.6 }}>
                例如："这个漏洞的修复方案是什么？"
              </p>
            </div>
          )}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
            {messages.map((msg) => (
              <div
                key={msg.id}
                style={{
                  display: 'flex',
                  gap: '10px',
                  flexDirection: msg.role === 'user' ? 'row-reverse' : 'row',
                  alignItems: 'flex-start',
                }}
              >
                {/* Avatar */}
                <div
                  style={{
                    width: '32px',
                    height: '32px',
                    borderRadius: '50%',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    flexShrink: 0,
                    background:
                      msg.role === 'user'
                        ? 'var(--accent-gradient)'
                        : 'rgba(148,163,184,0.08)',
                    color: msg.role === 'user' ? 'white' : 'var(--accent-start)',
                  }}
                >
                  {msg.role === 'user' ? <User size={16} /> : <Bot size={16} />}
                </div>
                {/* Bubble */}
                <div
                  style={{
                    maxWidth: '75%',
                    borderRadius: msg.role === 'user'
                      ? '16px 16px 4px 16px'
                      : '16px 16px 16px 4px',
                    padding: '12px 16px',
                    background:
                      msg.role === 'user'
                        ? 'var(--accent-gradient)'
                        : 'rgba(148,163,184,0.04)',
                    border: msg.role === 'assistant' ? '1px solid var(--border-light)' : 'none',
                    color: msg.role === 'user' ? 'white' : 'var(--text-primary)',
                  }}
                >
                  <div
                    className={msg.role === 'assistant' ? 'chat-markdown' : ''}
                    style={{ fontSize: '14px', lineHeight: 1.6, whiteSpace: 'pre-wrap' }}
                    dangerouslySetInnerHTML={
                      msg.role === 'assistant'
                        ? {
                            __html:
                              (marked.parse(msg.content) as string) +
                              (isChatTyping && msg.id === messages[messages.length - 1]?.id && msg.role === 'assistant'
                                ? '<span class="chat-typing-cursor"></span>'
                                : ''),
                          }
                        : undefined
                    }
                  >
                    {msg.role === 'user' ? msg.content : null}
                  </div>
                  {!(isChatTyping && msg.role === 'assistant' && msg.id === messages[messages.length - 1]?.id) && (
                  <div
                    style={{
                      marginTop: '6px',
                      fontSize: '10px',
                      textAlign: msg.role === 'user' ? 'right' : 'left',
                      color: msg.role === 'user' ? 'rgba(255,255,255,0.6)' : 'var(--text-muted)',
                    }}
                  >
                    {msg.time}
                  </div>
                  )}
                </div>
              </div>
            ))}
            {isWaitingResponse && (
              <div style={{ display: 'flex', gap: '10px', alignItems: 'flex-start' }}>
                <div
                  style={{
                    width: '32px',
                    height: '32px',
                    borderRadius: '50%',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    flexShrink: 0,
                    background: 'rgba(148,163,184,0.08)',
                    color: 'var(--accent-start)',
                  }}
                >
                  <Bot size={16} />
                </div>
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    borderRadius: '16px 16px 16px 4px',
                    padding: '14px 20px',
                    background: 'rgba(148,163,184,0.04)',
                    border: '1px solid var(--border-light)',
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
              alignItems: 'flex-end',
              gap: '12px',
              borderRadius: '12px',
              border: '1px solid var(--border-normal)',
              padding: '8px 12px',
              transition: 'border-color 0.15s',
              background: 'var(--bg-card)',
            }}
            onFocus={(e) => {
              e.currentTarget.style.borderColor = 'var(--border-focus)'
            }}
            onBlur={(e) => {
              e.currentTarget.style.borderColor = 'var(--border-normal)'
            }}
          >
            <textarea
              ref={chatInputRef}
              value={chatInput}
              onChange={(e) => {
                setChatInput(e.target.value)
                if (chatError) setChatError(null)
                // Auto-resize textarea
                e.target.style.height = 'auto'
                e.target.style.height = Math.min(e.target.scrollHeight, 120) + 'px'
              }}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                  e.preventDefault()
                  handleSendMessage()
                }
              }}
              placeholder="追问关于分析结果的问题..."
              rows={1}
              style={{
                flex: 1,
                background: 'transparent',
                fontSize: '14px',
                lineHeight: 1.5,
                border: 'none',
                outline: 'none',
                color: 'var(--text-primary)',
                resize: 'none',
                maxHeight: '120px',
                fontFamily: 'inherit',
              }}
              disabled={isChatTyping || isWaitingResponse}
            />
            <button
              onClick={handleSendMessage}
              disabled={!chatInput.trim() || isChatTyping || isWaitingResponse}
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                borderRadius: '8px',
                padding: '8px',
                border: 'none',
                background: chatInput.trim() && !isChatTyping && !isWaitingResponse ? 'var(--accent-gradient)' : 'transparent',
                color: chatInput.trim() && !isChatTyping && !isWaitingResponse ? 'white' : 'var(--accent-start)',
                cursor: chatInput.trim() && !isChatTyping && !isWaitingResponse ? 'pointer' : 'not-allowed',
                opacity: chatInput.trim() && !isChatTyping && !isWaitingResponse ? 1 : 0.4,
                transition: 'background 0.15s, opacity 0.15s',
                flexShrink: 0,
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
    </>
  )

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
          {/* ─── 5.1-8: PDF Export with Progress ──────── */}
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '8px' }}>
            <button
              onClick={handleExport}
              disabled={pdfDownloading}
              style={{
                background: pdfDownloading ? 'rgba(91,163,255,0.6)' : 'var(--accent-gradient)',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                borderRadius: '12px',
                padding: '10px 20px',
                fontSize: '14px',
                fontWeight: 500,
                color: 'white',
                border: 'none',
                cursor: pdfDownloading ? 'not-allowed' : 'pointer',
                boxShadow: 'var(--shadow-brand)',
                transition: 'opacity 0.15s',
                opacity: pdfDownloading ? 0.8 : 1,
              }}
              onMouseEnter={(e) => { if (!pdfDownloading) e.currentTarget.style.opacity = '0.9' }}
              onMouseLeave={(e) => { if (!pdfDownloading) e.currentTarget.style.opacity = '1' }}
            >
              {pdfDownloading ? (
                <>
                  <Loader2 size={16} className="animate-spin" />
                  正在生成...
                </>
              ) : (
                <>
                  <Download size={16} />
                  导出 PDF 报告
                </>
              )}
            </button>
            {/* Download Progress */}
            {pdfDownloading && (
              <div style={{ width: '180px' }}>
                <Progress
                  percent={pdfProgress}
                  size="small"
                  strokeColor={{ '0%': 'var(--accent-start)', '100%': 'var(--accent-end)' }}
                  trailColor="rgba(148,163,184,0.1)"
                />
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ─── 5.1-7: Tabs - Structured View + Markdown Preview ── */}
      <Tabs
        defaultActiveKey="structured"
        type="card"
        onChange={(key) => {
          if (key === 'markdown') {
            loadMarkdownContent()
          }
        }}
        items={[
          {
            key: 'structured',
            label: (
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
                <FileText size={14} />
                结构化视图
              </span>
            ),
            children: structuredViewContent,
          },
          {
            key: 'markdown',
            label: (
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
                <FileCode size={14} />
                Markdown 预览
              </span>
            ),
            children: (
              <div
                style={{
                  borderRadius: '16px',
                  border: '1px solid var(--border-light)',
                  background: 'var(--bg-card)',
                  padding: '24px',
                  boxShadow: 'var(--shadow-sm)',
                  minHeight: '400px',
                }}
              >
                {markdownLoading ? (
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '64px' }}>
                    <Spin size="large" />
                    <span style={{ marginLeft: '12px', fontSize: '14px', color: 'var(--text-secondary)' }}>
                      正在加载 Markdown 报告...
                    </span>
                  </div>
                ) : markdownContent ? (
                  <div
                    className="markdown-body dark-markdown"
                    dangerouslySetInnerHTML={{
                      __html: marked(markdownContent, { async: false }) as string,
                    }}
                  />
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '64px' }}>
                    <FileCode size={48} style={{ color: 'var(--text-muted)', marginBottom: '16px' }} />
                    <p style={{ fontSize: '14px', color: 'var(--text-secondary)' }}>
                      暂无 Markdown 报告内容
                    </p>
                  </div>
                )}
              </div>
            ),
          },
        ]}
        style={{ marginBottom: '0' }}
      />

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
