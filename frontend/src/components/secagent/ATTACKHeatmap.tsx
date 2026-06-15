import { useState, useMemo, useRef, useCallback } from 'react'
import { Download } from 'lucide-react'

// ─── Types ──────────────────────────────────────────
export interface ATTCKTechnique {
  id: string           // e.g., "T1190"
  name: string         // e.g., "Exploit Public-Facing Application"
  tactic: string       // e.g., "initial_access"
  confidence: number   // 0-100
  description?: string
}

interface ATTACKHeatmapProps {
  techniques: ATTCKTechnique[]
}

// ─── ATT&CK Matrix Template ─────────────────────────
// Comprehensive set of MITRE ATT&CK techniques organized by tactic
interface MatrixTechnique {
  id: string
  name: string
  subtechniques?: { id: string; name: string }[]
}

interface TacticColumn {
  key: string
  name: string
  nameCn: string
  techniques: MatrixTechnique[]
}

const ATTACK_MATRIX: TacticColumn[] = [
  {
    key: 'initial_access',
    name: 'Initial Access',
    nameCn: '初始访问',
    techniques: [
      { id: 'T1190', name: 'Exploit Public-Facing Application' },
      { id: 'T1133', name: 'External Remote Services' },
      { id: 'T1200', name: 'Hardware Additions' },
      { id: 'T1189', name: 'Drive-by Compromise' },
      { id: 'T1091', name: 'Replication Through Removable Media' },
      { id: 'T1078', name: 'Valid Accounts' },
      { id: 'T1195', name: 'Supply Chain Compromise', subtechniques: [
        { id: 'T1195.001', name: 'Supply Chain Compromise: Software Supply Chain' },
        { id: 'T1195.002', name: 'Supply Chain Compromise: Hardware Supply Chain' },
      ] },
      { id: 'T1199', name: 'Trusted Relationship' },
      { id: 'T1078', name: 'Valid Accounts' },
    ],
  },
  {
    key: 'execution',
    name: 'Execution',
    nameCn: '执行',
    techniques: [
      { id: 'T1059', name: 'Command and Scripting Interpreter', subtechniques: [
        { id: 'T1059.001', name: 'PowerShell' },
        { id: 'T1059.003', name: 'Windows Command Shell' },
        { id: 'T1059.004', name: 'Unix Shell' },
        { id: 'T1059.005', name: 'Visual Basic' },
        { id: 'T1059.006', name: 'Python' },
        { id: 'T1059.007', name: 'JavaScript' },
      ] },
      { id: 'T1609', name: 'Container Administration Command' },
      { id: 'T1053', name: 'Scheduled Task/Job' },
      { id: 'T1204', name: 'User Execution' },
      { id: 'T1046', name: 'Windows Management Instrumentation' },
      { id: 'T1559', name: 'Inter-Process Communication' },
      { id: 'T1129', name: 'Shared Modules' },
    ],
  },
  {
    key: 'persistence',
    name: 'Persistence',
    nameCn: '持久化',
    techniques: [
      { id: 'T1547', name: 'Boot or Logon Autostart Execution' },
      { id: 'T1136', name: 'Create Account' },
      { id: 'T1543', name: 'Create or Modify System Process' },
      { id: 'T1133', name: 'External Remote Services' },
      { id: 'T1542', name: 'Pre-OS Boot' },
      { id: 'T1053', name: 'Scheduled Task/Job' },
      { id: 'T1574', name: 'Hijack Execution Flow' },
      { id: 'T1197', name: 'BITS Jobs' },
      { id: 'T1078', name: 'Valid Accounts' },
      { id: 'T1137', name: 'Office Application Startup' },
    ],
  },
  {
    key: 'privilege_escalation',
    name: 'Privilege Escalation',
    nameCn: '权限提升',
    techniques: [
      { id: 'T1548', name: 'Abuse Elevation Control Mechanism' },
      { id: 'T1134', name: 'Access Token Manipulation' },
      { id: 'T1547', name: 'Boot or Logon Autostart Execution' },
      { id: 'T1543', name: 'Create or Modify System Process' },
      { id: 'T1055', name: 'Process Injection' },
      { id: 'T1574', name: 'Hijack Execution Flow' },
      { id: 'T1068', name: 'Exploitation for Privilege Escalation' },
      { id: 'T1078', name: 'Valid Accounts' },
      { id: 'T1053', name: 'Scheduled Task/Job' },
      { id: 'T1036', name: 'Masquerading' },
    ],
  },
  {
    key: 'defense_evasion',
    name: 'Defense Evasion',
    nameCn: '防御规避',
    techniques: [
      { id: 'T1055', name: 'Process Injection' },
      { id: 'T1134', name: 'Access Token Manipulation' },
      { id: 'T1140', name: 'Deobfuscate/Decode Files or Information' },
      { id: 'T1027', name: 'Obfuscated Files or Information' },
      { id: 'T1036', name: 'Masquerading' },
      { id: 'T1057', name: 'Process Discovery' },
      { id: 'T1070', name: 'Indicator Removal' },
      { id: 'T1562', name: 'Impair Defenses' },
      { id: 'T1078', name: 'Valid Accounts' },
      { id: 'T1218', name: 'System Binary Proxy Execution' },
      { id: 'T1202', name: 'Indirect Command Execution' },
      { id: 'T1574', name: 'Hijack Execution Flow' },
    ],
  },
  {
    key: 'credential_access',
    name: 'Credential Access',
    nameCn: '凭证访问',
    techniques: [
      { id: 'T1110', name: 'Brute Force' },
      { id: 'T1552', name: 'Unsecured Credentials' },
      { id: 'T1003', name: 'OS Credential Dumping' },
      { id: 'T1558', name: 'Steal or Forge Kerberos Tickets' },
      { id: 'T1056', name: 'Input Capture' },
      { id: 'T1111', name: 'Multi-Factor Authentication Interception' },
      { id: 'T1212', name: 'Exploitation for Credential Access' },
      { id: 'T1040', name: 'Network Sniffing' },
      { id: 'T1606', name: 'Forge Web Credentials' },
    ],
  },
  {
    key: 'discovery',
    name: 'Discovery',
    nameCn: '发现',
    techniques: [
      { id: 'T1082', name: 'System Information Discovery' },
      { id: 'T1083', name: 'File and Directory Discovery' },
      { id: 'T1046', name: 'Network Service Discovery' },
      { id: 'T1018', name: 'Remote System Discovery' },
      { id: 'T1087', name: 'Account Discovery' },
      { id: 'T1057', name: 'Process Discovery' },
      { id: 'T1012', name: 'Query Registry' },
      { id: 'T1069', name: 'Permission Groups Discovery' },
      { id: 'T1049', name: 'System Network Connections Discovery' },
      { id: 'T1135', name: 'Network Share Discovery' },
    ],
  },
  {
    key: 'lateral_movement',
    name: 'Lateral Movement',
    nameCn: '横向移动',
    techniques: [
      { id: 'T1021', name: 'Remote Services' },
      { id: 'T1210', name: 'Exploitation of Remote Services' },
      { id: 'T1563', name: 'Remote Service Session Hijacking' },
      { id: 'T1072', name: 'Software Deployment Tools' },
      { id: 'T1080', name: 'Taint Shared Content' },
      { id: 'T1534', name: 'Internal Spearphishing' },
      { id: 'T1091', name: 'Replication Through Removable Media' },
      { id: 'T1570', name: 'Lateral Tool Transfer' },
    ],
  },
  {
    key: 'collection',
    name: 'Collection',
    nameCn: '收集',
    techniques: [
      { id: 'T1560', name: 'Archive Collected Data' },
      { id: 'T1005', name: 'Data from Local System' },
      { id: 'T1039', name: 'Data from Network Shared Drive' },
      { id: 'T1025', name: 'Data from Removable Media' },
      { id: 'T1114', name: 'Email Collection' },
      { id: 'T1113', name: 'Screen Capture' },
      { id: 'T1123', name: 'Audio Capture' },
      { id: 'T1056', name: 'Input Capture' },
    ],
  },
  {
    key: 'exfiltration',
    name: 'Exfiltration',
    nameCn: '数据渗出',
    techniques: [
      { id: 'T1041', name: 'Exfiltration Over C2 Channel' },
      { id: 'T1567', name: 'Exfiltration Over Web Service' },
      { id: 'T1048', name: 'Exfiltration Over Alternative Protocol' },
      { id: 'T1011', name: 'Exfiltration Over Other Network Medium' },
      { id: 'T1052', name: 'Exfiltration Over Physical Medium' },
      { id: 'T1560', name: 'Archive Collected Data' },
    ],
  },
  {
    key: 'command_and_control',
    name: 'Command and Control',
    nameCn: '命令控制',
    techniques: [
      { id: 'T1071', name: 'Application Layer Protocol' },
      { id: 'T1095', name: 'Non-Application Layer Protocol' },
      { id: 'T1132', name: 'Data Encoding' },
      { id: 'T1001', name: 'Data Obfuscation' },
      { id: 'T1105', name: 'Ingress Tool Transfer' },
      { id: 'T1104', name: 'Multi-Stage Channels' },
      { id: 'T1090', name: 'Proxy' },
      { id: 'T1572', name: 'Protocol Tunneling' },
      { id: 'T1573', name: 'Encrypted Channel' },
      { id: 'T1188', name: 'Multi-Hop Proxy' },
      { id: 'T1102', name: 'Web Service' },
    ],
  },
]

// ─── Tooltip Component ──────────────────────────────
function HeatmapTooltip({
  visible,
  x,
  y,
  technique,
}: {
  visible: boolean
  x: number
  y: number
  technique: {
    id: string
    name: string
    tactic: string
    status: 'detected' | 'potential' | 'undetected'
    confidence: number
    description?: string
  } | null
}) {
  if (!visible || !technique) return null

  const statusLabels = {
    detected: '已检测',
    potential: '潜在相关',
    undetected: '未检测',
  }
  const statusColors = {
    detected: '#EF4444',
    potential: '#F59E0B',
    undetected: '#94A3B8',
  }

  return (
    <div
      style={{
        pointerEvents: 'none',
        position: 'fixed',
        zIndex: 50,
        borderRadius: '12px',
        border: '1px solid var(--border-light)',
        background: 'var(--bg-card)',
        padding: '12px 16px',
        boxShadow: 'var(--shadow-lg)',
        left: Math.min(x, typeof window !== 'undefined' ? window.innerWidth - 260 : x),
        top: y - 10,
        transform: 'translateY(-100%)',
        maxWidth: '240px',
      }}
    >
      <div style={{ marginBottom: '4px', display: 'flex', alignItems: 'center', gap: '8px' }}>
        <span
          style={{
            borderRadius: '6px',
            padding: '2px 6px',
            fontSize: '11px',
            fontWeight: 700,
            background: technique.status === 'detected'
              ? 'rgba(239,68,68,0.1)'
              : technique.status === 'potential'
                ? 'rgba(245,158,11,0.1)'
                : 'rgba(148,163,184,0.08)',
            color: statusColors[technique.status],
          }}
        >
          {technique.id}
        </span>
        <span
          style={{
            fontSize: '11px',
            fontWeight: 600,
            color: statusColors[technique.status],
          }}
        >
          {statusLabels[technique.status]}
        </span>
      </div>
      <div style={{ marginBottom: '4px', fontSize: '12px', fontWeight: 500, color: 'var(--text-primary)' }}>
        {technique.name}
      </div>
      {technique.status !== 'undetected' && (
        <div style={{ marginBottom: '4px', fontSize: '11px', color: 'var(--text-secondary)' }}>
          置信度: {technique.confidence}%
        </div>
      )}
      {technique.description && (
        <div style={{ fontSize: '11px', lineHeight: '1.6', color: 'var(--text-muted)' }}>
          {technique.description}
        </div>
      )}
      <div style={{ marginTop: '4px', fontSize: '10px', color: 'var(--text-muted)' }}>
        战术: {technique.tactic}
      </div>
    </div>
  )
}

// ─── Main Component ─────────────────────────────────
export default function ATTACKHeatmap({ techniques }: ATTACKHeatmapProps) {
  const containerRef = useRef<HTMLDivElement>(null)
  const [tooltip, setTooltip] = useState<{
    visible: boolean
    x: number
    y: number
    technique: {
      id: string
      name: string
      tactic: string
      status: 'detected' | 'potential' | 'undetected'
      confidence: number
      description?: string
    } | null
  }>({ visible: false, x: 0, y: 0, technique: null })

  const exportToImage = useCallback(() => {
    if (!containerRef.current) return
    const el = containerRef.current
    const svgElement = el.querySelector('svg')
    if (svgElement) {
      const svgData = new XMLSerializer().serializeToString(svgElement)
      const canvas = document.createElement('canvas')
      const ctx = canvas.getContext('2d')
      if (!ctx) return
      const img = new Image()
      img.onload = () => {
        canvas.width = img.width * 2
        canvas.height = img.height * 2
        ctx.scale(2, 2)
        ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--bg-card').trim() || '#ffffff'
        ctx.fillRect(0, 0, img.width, img.height)
        ctx.drawImage(img, 0, 0)
        const link = document.createElement('a')
        link.download = 'ATTACK热力图.png'
        link.href = canvas.toDataURL('image/png')
        link.click()
      }
      img.src = 'data:image/svg+xml;base64,' + btoa(unescape(encodeURIComponent(svgData)))
    }
  }, [])

  // Build lookup map from detected techniques
  const techniqueMap = useMemo(() => {
    const map = new Map<string, ATTCKTechnique>()
    for (const t of techniques) {
      // Store both with and without subtechnique notation
      map.set(t.id.toLowerCase(), t)
      // Also store base technique ID (e.g., T1190 from T1190.001)
      const baseId = t.id.split('.')[0].toLowerCase()
      if (!map.has(baseId)) {
        map.set(baseId, t)
      }
    }
    return map
  }, [techniques])

  // Get technique status and styling
  const getTechniqueStatus = (techId: string): {
    status: 'detected' | 'potential' | 'undetected'
    confidence: number
    bgColor: string
    textColor: string
    borderColor: string
    detected: ATTCKTechnique | undefined
  } => {
    const normalizedId = techId.toLowerCase()
    const detected = techniqueMap.get(normalizedId)
    // Also check base ID
    const baseId = techId.split('.')[0].toLowerCase()
    const detectedBase = techniqueMap.get(baseId)

    const match = detected || detectedBase

    if (match) {
      const confidence = match.confidence ?? 50
      if (confidence >= 60) {
        const opacity = 0.25 + (confidence / 100) * 0.55
        return {
          status: 'detected',
          confidence,
          bgColor: `rgba(239, 68, 68, ${opacity})`,
          textColor: '#DC2626',
          borderColor: `rgba(239, 68, 68, ${opacity + 0.15})`,
          detected: match,
        }
      } else {
        const opacity = 0.2 + (confidence / 100) * 0.4
        return {
          status: 'potential',
          confidence,
          bgColor: `rgba(245, 158, 11, ${opacity})`,
          textColor: '#D97706',
          borderColor: `rgba(245, 158, 11, ${opacity + 0.15})`,
          detected: match,
        }
      }
    }

    return {
      status: 'undetected',
      confidence: 0,
      bgColor: 'rgba(148, 163, 184, 0.06)',
      textColor: '#94A3B8',
      borderColor: 'rgba(148, 163, 184, 0.12)',
      detected: undefined,
    }
  }

  const handleMouseEnter = (
    e: React.MouseEvent,
    techId: string,
    techName: string,
    tacticName: string,
  ) => {
    const { status, confidence, detected } = getTechniqueStatus(techId)
    setTooltip({
      visible: true,
      x: e.clientX,
      y: e.clientY,
      technique: {
        id: techId,
        name: techName,
        tactic: tacticName,
        status,
        confidence,
        description: detected?.description,
      },
    })
  }

  const handleMouseMove = (e: React.MouseEvent) => {
    setTooltip((prev) => prev.visible ? { ...prev, x: e.clientX, y: e.clientY } : prev)
  }

  const handleMouseLeave = () => {
    setTooltip({ visible: false, x: 0, y: 0, technique: null })
  }

  // Count stats for summary
  const stats = useMemo(() => {
    let detected = 0
    let potential = 0
    let total = 0
    for (const col of ATTACK_MATRIX) {
      for (const tech of col.techniques) {
        total++
        const { status } = getTechniqueStatus(tech.id)
        if (status === 'detected') detected++
        else if (status === 'potential') potential++
      }
    }
    return { detected, potential, total }
  }, [techniqueMap])

  return (
    <div
      ref={containerRef}
      className="animate-slide-up"
      style={{
        borderRadius: '16px',
        border: '1px solid var(--border-light)',
        background: 'var(--bg-card)',
        overflow: 'hidden',
        boxShadow: 'var(--shadow-sm)',
      }}
    >
      {/* Header */}
      <div
        style={{
          borderBottom: '1px solid var(--border-light)',
          padding: '16px',
          borderColor: 'var(--border-light)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div>
            <h2
              style={{
                fontWeight: 600,
                fontSize: '18px',
                color: 'var(--text-primary)',
              }}
            >
              ATT&CK 热力图
            </h2>
            <p style={{ marginTop: '2px', fontSize: '14px', color: 'var(--text-secondary)' }}>
              MITRE ATT&CK 技术覆盖分析
            </p>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <button
              onClick={exportToImage}
              title="导出为图片"
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                width: '28px',
                height: '28px',
                borderRadius: '8px',
                border: '1px solid var(--border-light)',
                background: 'var(--bg-card)',
                cursor: 'pointer',
                transition: 'all 0.15s',
                flexShrink: 0,
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.borderColor = 'var(--border-focus)'
                e.currentTarget.style.color = 'var(--accent-start)'
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.borderColor = 'var(--border-light)'
                e.currentTarget.style.color = 'var(--text-muted)'
              }}
            >
              <Download size={13} style={{ color: 'inherit' }} />
            </button>
            <span
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                borderRadius: '8px',
                padding: '4px 10px',
                fontSize: '12px',
                fontWeight: 600,
                background: 'rgba(239,68,68,0.08)',
                color: '#EF4444',
              }}
            >
              <span
                style={{
                  display: 'inline-block',
                  width: '8px',
                  height: '8px',
                  borderRadius: '50%',
                  background: '#EF4444',
                }}
              />
              {stats.detected} 已检测
            </span>
            <span
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                borderRadius: '8px',
                padding: '4px 10px',
                fontSize: '12px',
                fontWeight: 600,
                background: 'rgba(245,158,11,0.08)',
                color: '#F59E0B',
              }}
            >
              <span
                style={{
                  display: 'inline-block',
                  width: '8px',
                  height: '8px',
                  borderRadius: '50%',
                  background: '#F59E0B',
                }}
              />
              {stats.potential} 潜在
            </span>
          </div>
        </div>
      </div>

      {/* Matrix Grid - scrollable on mobile */}
      <div style={{ overflowX: 'auto', WebkitOverflowScrolling: 'touch' as const }}>
        <div style={{ minWidth: '900px', padding: '16px' }}>
          {/* Tactic Headers */}
          <div
            style={{
              display: 'grid',
              gap: '4px',
              marginBottom: '4px',
              gridTemplateColumns: `repeat(${ATTACK_MATRIX.length}, minmax(70px, 1fr))`,
            }}
          >
            {ATTACK_MATRIX.map((tactic) => {
              // Count detected in this tactic
              let tacticDetected = 0
              for (const tech of tactic.techniques) {
                const { status } = getTechniqueStatus(tech.id)
                if (status !== 'undetected') tacticDetected++
              }

              return (
                <div
                  key={tactic.key}
                  style={{
                    textAlign: 'center',
                    borderRadius: '8px',
                    padding: '8px 4px',
                    background: tacticDetected > 0
                      ? 'linear-gradient(135deg, rgba(91,163,255,0.06), rgba(94,234,212,0.06))'
                      : 'rgba(148,163,184,0.03)',
                  }}
                >
                  <div
                    style={{
                      fontSize: '11px',
                      fontWeight: 700,
                      lineHeight: '1.25',
                      marginBottom: '2px',
                      color: tacticDetected > 0 ? 'var(--accent-start)' : 'var(--text-muted)',
                    }}
                  >
                    {tactic.nameCn}
                  </div>
                  <div
                    style={{
                      fontSize: '9px',
                      lineHeight: '1.25',
                      color: 'var(--text-muted)',
                    }}
                  >
                    {tactic.name}
                  </div>
                  {tacticDetected > 0 && (
                    <div
                      style={{
                        marginTop: '4px',
                        fontSize: '9px',
                        fontWeight: 600,
                        color: 'var(--accent-start)',
                      }}
                    >
                      {tacticDetected}/{tactic.techniques.length}
                    </div>
                  )}
                </div>
              )
            })}
          </div>

          {/* Technique Cells */}
          <div
            style={{
              display: 'grid',
              gap: '4px',
              gridTemplateColumns: `repeat(${ATTACK_MATRIX.length}, minmax(70px, 1fr))`,
            }}
          >
            {(() => {
              // Build rows: find max techniques per tactic
              const maxRows = Math.max(...ATTACK_MATRIX.map((t) => t.techniques.length))
              const rows: React.ReactNode[] = []

              for (let rowIdx = 0; rowIdx < maxRows; rowIdx++) {
                for (let colIdx = 0; colIdx < ATTACK_MATRIX.length; colIdx++) {
                  const tactic = ATTACK_MATRIX[colIdx]
                  const tech = tactic.techniques[rowIdx]

                  if (!tech) {
                    rows.push(
                      <div
                        key={`empty-${colIdx}-${rowIdx}`}
                        style={{ borderRadius: '8px', minHeight: '32px' }}
                      />
                    )
                    continue
                  }

                  const { status, confidence, bgColor, textColor, borderColor } = getTechniqueStatus(tech.id)
                  const isDetected = status !== 'undetected'

                  rows.push(
                    <div
                      key={`${tech.id}-${colIdx}-${rowIdx}`}
                      style={{
                        position: 'relative',
                        borderRadius: '8px',
                        padding: '6px',
                        cursor: 'default',
                        transition: 'all 0.2s',
                        background: bgColor,
                        border: `1px solid ${borderColor}`,
                        minHeight: '32px',
                      }}
                      onMouseEnter={(e) =>
                        handleMouseEnter(e, tech.id, tech.name, `${tactic.nameCn} (${tactic.name})`)
                      }
                      onMouseMove={handleMouseMove}
                      onMouseLeave={handleMouseLeave}
                    >
                      {/* Hover overlay */}
                      {isDetected && (
                        <div
                          style={{
                            position: 'absolute',
                            inset: 0,
                            borderRadius: '8px',
                            opacity: 0,
                            transition: 'opacity 0.2s',
                            pointerEvents: 'none',
                            background: status === 'detected'
                              ? 'rgba(239,68,68,0.06)'
                              : 'rgba(245,158,11,0.06)',
                          }}
                          onMouseEnter={(e) => {
                            // Show hover effect via JS since we can't use :hover in inline styles
                            (e.currentTarget as HTMLDivElement).style.opacity = '1';
                          }}
                          onMouseLeave={(e) => {
                            (e.currentTarget as HTMLDivElement).style.opacity = '0';
                          }}
                        />
                      )}
                      <div style={{ position: 'relative' }}>
                        <div
                          style={{
                            fontSize: '10px',
                            fontWeight: 700,
                            lineHeight: '1.25',
                            color: textColor,
                          }}
                        >
                          {tech.id}
                        </div>
                        <div
                          style={{
                            fontSize: '8px',
                            lineHeight: '1.25',
                            marginTop: '2px',
                            overflow: 'hidden',
                            display: '-webkit-box',
                            WebkitLineClamp: 2,
                            WebkitBoxOrient: 'vertical' as const,
                            color: isDetected ? textColor : 'var(--text-muted)',
                            opacity: isDetected ? 0.8 : 0.6,
                          }}
                        >
                          {tech.name.length > 28 ? tech.name.substring(0, 26) + '...' : tech.name}
                        </div>
                        {isDetected && (
                          <div
                            style={{
                              marginTop: '2px',
                              height: '4px',
                              borderRadius: '9999px',
                              overflow: 'hidden',
                              background: 'rgba(148,163,184,0.1)',
                            }}
                          >
                            <div
                              style={{
                                height: '100%',
                                borderRadius: '9999px',
                                transition: 'all 0.5s',
                                width: `${confidence}%`,
                                background: status === 'detected'
                                  ? 'linear-gradient(90deg, #EF4444, #F87171)'
                                  : 'linear-gradient(90deg, #F59E0B, #FBBF24)',
                              }}
                            />
                          </div>
                        )}
                      </div>
                    </div>
                  )
                }
              }

              return rows
            })()}
          </div>
        </div>
      </div>

      {/* Legend */}
      <div
        style={{
          borderTop: '1px solid var(--border-light)',
          padding: '12px 16px',
          display: 'flex',
          flexWrap: 'wrap',
          alignItems: 'center',
          gap: '16px',
          borderColor: 'var(--border-light)',
        }}
      >
        <span style={{ fontSize: '12px', fontWeight: 500, color: 'var(--text-secondary)' }}>
          图例:
        </span>
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <div
            style={{
              height: '16px',
              width: '16px',
              borderRadius: '4px',
              background: 'rgba(239, 68, 68, 0.6)',
              border: '1px solid rgba(239,68,68,0.7)',
            }}
          />
          <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
            已检测（高置信度）
          </span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <div
            style={{
              height: '16px',
              width: '16px',
              borderRadius: '4px',
              background: 'rgba(245, 158, 11, 0.4)',
              border: '1px solid rgba(245,158,11,0.5)',
            }}
          />
          <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
            潜在相关
          </span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <div
            style={{
              height: '16px',
              width: '16px',
              borderRadius: '4px',
              background: 'rgba(148, 163, 184, 0.06)',
              border: '1px solid rgba(148,163,184,0.12)',
            }}
          />
          <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
            未检测
          </span>
        </div>
        <div style={{ marginLeft: 'auto', fontSize: '11px', color: 'var(--text-muted)' }}>
          共 {stats.total} 项技术 · {stats.detected + stats.potential} 项命中
        </div>
      </div>

      {/* Tooltip */}
      <HeatmapTooltip
        visible={tooltip.visible}
        x={tooltip.x}
        y={tooltip.y}
        technique={tooltip.technique}
      />
    </div>
  )
}
