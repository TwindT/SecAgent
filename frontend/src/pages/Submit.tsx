import { useState, useMemo } from 'react'
import {
  Code2,
  Bug,
  Upload,
  FileText,
  X,
  Play,
  ChevronDown,
  Copy,
  Check,
  AlertCircle,
  CheckCircle2,
  Eye,
  Pencil,
  BarChart3,
  Layers,
  GitBranch,
} from 'lucide-react'
import { createTask } from '@/services/api'
import { message } from 'antd'
import { useNavigate, useSearchParams } from 'react-router-dom'

// ─── Mock code for demo ─────────────────────────────
const sampleCode = `import sqlite3

def get_user(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # Vulnerable: SQL injection via string formatting
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    result = cursor.fetchone()
    conn.close()
    return result

def delete_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = "DELETE FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    conn.commit()
    conn.close()`

// ─── Syntax Highlighting Engine ─────────────────────
const PYTHON_KEYWORDS = new Set([
  'import', 'from', 'def', 'class', 'return', 'if', 'elif', 'else', 'for', 'while',
  'try', 'except', 'finally', 'with', 'as', 'yield', 'lambda', 'and', 'or', 'not',
  'in', 'is', 'True', 'False', 'None', 'pass', 'break', 'continue', 'raise', 'del',
  'global', 'nonlocal', 'assert', 'async', 'await',
])

const JS_KEYWORDS = new Set([
  'import', 'from', 'export', 'default', 'const', 'let', 'var', 'function', 'return',
  'if', 'else', 'for', 'while', 'do', 'switch', 'case', 'break', 'continue', 'try',
  'catch', 'finally', 'throw', 'new', 'this', 'class', 'extends', 'super', 'typeof',
  'instanceof', 'in', 'of', 'true', 'false', 'null', 'undefined', 'async', 'await',
  'yield', 'void', 'delete',
])

const PYTHON_BUILTINS = new Set([
  'print', 'len', 'range', 'str', 'int', 'float', 'list', 'dict', 'set', 'tuple',
  'open', 'type', 'isinstance', 'enumerate', 'zip', 'map', 'filter', 'sorted',
  'append', 'connect', 'cursor', 'execute', 'fetchone', 'commit', 'close',
])

const JS_BUILTINS = new Set([
  'console', 'log', 'Math', 'JSON', 'String', 'Number', 'Array', 'Object',
  'Promise', 'fetch', 'document', 'window', 'addEventListener', 'querySelector',
  'parseInt', 'parseFloat', 'setTimeout', 'setInterval',
])

function highlightLine(line: string, language: string): Array<{ text: string; type: 'normal' | 'keyword' | 'string' | 'comment' | 'builtin' | 'number' | 'decorator' }> {
  const tokens: Array<{ text: string; type: 'normal' | 'keyword' | 'string' | 'comment' | 'builtin' | 'number' | 'decorator' }> = []

  const keywords = language === 'python' ? PYTHON_KEYWORDS : JS_KEYWORDS
  const builtins = language === 'python' ? PYTHON_BUILTINS : JS_BUILTINS

  // Check for full-line comment
  const trimmed = line.trimStart()
  if (trimmed.startsWith('#') || trimmed.startsWith('//')) {
    tokens.push({ text: line, type: 'comment' })
    return tokens
  }

  let i = 0
  while (i < line.length) {
    // Python decorator
    if (language === 'python' && line[i] === '@' && (i === 0 || line[i - 1] === ' ')) {
      let end = i + 1
      while (end < line.length && /[\w.]/.test(line[end])) end++
      tokens.push({ text: line.slice(i, end), type: 'decorator' })
      i = end
      continue
    }

    // Strings
    if (line[i] === '"' || line[i] === "'" || (line[i] === '`' && language !== 'python')) {
      const quote = line[i]
      let end = i + 1
      while (end < line.length && line[end] !== quote) {
        if (line[end] === '\\') end++ // skip escaped
        end++
      }
      if (end < line.length) end++ // include closing quote
      // Check for f-string prefix
      const prefix = i > 0 && line[i - 1] === 'f' ? 'f' : ''
      const startIdx = prefix ? i - 1 : i
      tokens.push({ text: line.slice(startIdx, end), type: 'string' })
      i = end
      continue
    }

    // Inline comment
    if (line[i] === '#' || (line[i] === '/' && i + 1 < line.length && line[i + 1] === '/')) {
      tokens.push({ text: line.slice(i), type: 'comment' })
      i = line.length
      continue
    }

    // Numbers
    if (/[0-9]/.test(line[i]) && (i === 0 || /[\s(,=+\-*/<>[\]{}!]/.test(line[i - 1]))) {
      let end = i
      while (end < line.length && /[0-9.xXa-fA-F]/.test(line[end])) end++
      tokens.push({ text: line.slice(i, end), type: 'number' })
      i = end
      continue
    }

    // Identifiers / keywords
    if (/[a-zA-Z_]/.test(line[i])) {
      let end = i
      while (end < line.length && /[\w]/.test(line[end])) end++
      const word = line.slice(i, end)
      if (keywords.has(word)) {
        tokens.push({ text: word, type: 'keyword' })
      } else if (builtins.has(word)) {
        tokens.push({ text: word, type: 'builtin' })
      } else {
        tokens.push({ text: word, type: 'normal' })
      }
      i = end
      continue
    }

    // Other characters
    tokens.push({ text: line[i], type: 'normal' })
    i++
  }

  return tokens
}

const TOKEN_COLORS: Record<string, string> = {
  keyword: '#C792EA',   // purple for keywords
  string: '#C3E88D',    // green for strings
  comment: '#546E7A',   // gray for comments
  builtin: '#82AAFF',   // light blue for builtins
  number: '#F78C6C',    // orange for numbers
  decorator: '#FFCB6B', // yellow for decorators
  normal: '#E2E8F0',    // default light gray
}

// ─── Code Complexity Estimator ──────────────────────
function estimateComplexity(code: string, language: string) {
  const lines = code.split('\n')
  const nonEmptyLines = lines.filter(l => l.trim().length > 0)

  // Count functions
  const funcPattern = language === 'python'
    ? /^(?:async\s+)?def\s+\w+/
    : /^(?:function\s+\w+|(?:const|let|var)\s+\w+\s*=\s*(?:async\s+)?(?:function|\(|\w+\s*=>))/m
  const funcCount = (code.match(new RegExp(funcPattern.source, 'gm')) || []).length

  // Count nesting depth (simple heuristic: count indentation levels for Python, braces for JS)
  let maxNesting = 0
  if (language === 'python') {
    nonEmptyLines.forEach(line => {
      const indent = line.length - line.trimStart().length
      const level = Math.floor(indent / 4)
      maxNesting = Math.max(maxNesting, level)
    })
  } else {
    let depth = 0
    for (const ch of code) {
      if (ch === '{') { depth++; maxNesting = Math.max(maxNesting, depth) }
      if (ch === '}') depth--
    }
  }

  // Count conditional branches
  const condPattern = language === 'python'
    ? /^\s*(?:if|elif|else|for|while|try|except|with)/
    : /(?:if|else|for|while|switch|try|catch)\s*[\({]/
  const condCount = (code.match(new RegExp(condPattern.source, 'gm')) || []).length

  // Simple complexity score: based on nesting + conditions + function count
  const score = Math.min(100, Math.round(
    (maxNesting * 15) + (condCount * 8) + (funcCount * 5) + (nonEmptyLines.length * 0.3)
  ))

  let level = '低'
  let levelColor = '#10B981'
  if (score > 60) { level = '高'; levelColor = '#EF4444' }
  else if (score > 30) { level = '中'; levelColor = '#F59E0B' }

  return { score, level, levelColor, funcCount, maxNesting, condCount }
}

const Submit = () => {
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const defaultTab = searchParams.get('tab')

  const [activeTab, setActiveTab] = useState<'code' | 'malware'>(
    defaultTab === 'malware' ? 'malware' : 'code'
  )
  const [code, setCode] = useState(sampleCode)
  const [language, setLanguage] = useState('python')
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [inputMode, setInputMode] = useState<'paste' | 'upload'>('paste')
  const [codeViewMode, setCodeViewMode] = useState<'edit' | 'preview'>('edit')
  const [uploadedFiles, setUploadedFiles] = useState<File[]>([])
  const [isDragOver, setIsDragOver] = useState(false)
  const [copied, setCopied] = useState(false)
  const [taskName, setTaskName] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState(false)

  const languages = [
    { value: 'python', label: 'Python' },
    { value: 'javascript', label: 'JavaScript' },
    { value: 'java', label: 'Java' },
    { value: 'go', label: 'Go' },
    { value: 'c', label: 'C/C++' },
    { value: 'rust', label: 'Rust' },
  ]

  // Code stats
  const codeStats = useMemo(() => {
    const lines = code.split('\n')
    const lineCount = lines.length
    const charCount = code.length
    const nonEmptyCount = lines.filter(l => l.trim().length > 0).length
    const complexity = estimateComplexity(code, language)
    return { lineCount, charCount, nonEmptyCount, complexity }
  }, [code, language])

  const deriveTaskName = () => {
    if (taskName.trim()) return taskName.trim()
    if (activeTab === 'code') {
      // Try to find function/class definition for a meaningful name
      const defPatterns = [
        /^(?:def|async\s+def)\s+(\w+)/m,       // Python: def func_name
        /^(?:function|const|let|var)\s+(\w+)/m, // JavaScript: function name / const name
        /^(?:public|private|protected)?\s*(?:static\s+)?(?:void|\S+)\s+(\w+)\s*\(/m, // Java/C#
        /^(?:func)\s+(\w+)/m,                    // Go: func name
        /^(?:fn)\s+(\w+)/m,                      // Rust: fn name
        /^(?:class)\s+(\w+)/m,                    // class Name
      ]
      for (const pattern of defPatterns) {
        const match = code.match(pattern)
        if (match?.[1]) return `${match[1]}.${language === 'python' ? 'py' : language === 'javascript' ? 'js' : language === 'java' ? 'java' : language === 'go' ? 'go' : language === 'c' ? 'c' : language === 'rust' ? 'rs' : 'txt'}`
      }
      // Fallback: language_scan_timestamp
      const langLabel = languages.find((l) => l.value === language)?.label || language
      return `${langLabel}_code_scan`
    }
    return uploadedFiles[0]?.name || 'untitled_file'
  }

  const handleSubmit = async () => {
    setError(null)
    setIsSubmitting(true)
    try {
      if (activeTab === 'code') {
        const result = await createTask({
          type: 'vulnerability_detection',
          input_content: code,
        })
        setSuccess(true)
        message.success('任务创建成功，正在跳转到分析页面...')
        const taskId = result.data.task_id
        setTimeout(() => {
          navigate(`/analysis/${taskId}`)
        }, 600)
      } else {
        const result = await createTask({
          type: 'malware_analysis',
          input_path: 'upload/' + (uploadedFiles[0]?.name || 'untitled_file'),
        })
        setSuccess(true)
        message.success('恶意代码分析任务已创建，正在跳转到分析页面...')
        const taskId = result.data.task_id
        setTimeout(() => {
          navigate(`/analysis/${taskId}`)
        }, 600)
      }
    } catch (err) {
      const errMsg = err instanceof Error ? err.message : '任务创建失败，请稍后重试'
      setError(errMsg)
      message.error('任务创建失败: ' + errMsg)
    } finally {
      setIsSubmitting(false)
    }
  }

  const handleCopy = () => {
    navigator.clipboard.writeText(code)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const handleFileDrop = (e: React.DragEvent) => {
    e.preventDefault()
    setIsDragOver(false)
    const files = Array.from(e.dataTransfer.files)
    setUploadedFiles((prev) => [...prev, ...files])
    if (error) setError(null)
  }

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) {
      const files = Array.from(e.target.files)
      setUploadedFiles((prev) => [...prev, ...files])
      if (error) setError(null)
    }
  }

  const removeFile = (index: number) => {
    setUploadedFiles((prev) => prev.filter((_, i) => i !== index))
  }

  const formatFileSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  }

  return (
    <div style={{ maxWidth: '1200px', margin: '0 auto', width: '100%', padding: '24px 16px' }}>
      {/* Page Title */}
      <div className="animate-slide-up" style={{ marginBottom: '24px' }}>
        <h1
          style={{
            fontWeight: 600,
            fontSize: '28px',
            lineHeight: '1.3',
            color: 'var(--text-primary)',
          }}
        >
          提交分析任务
        </h1>
        <p
          style={{
            marginTop: '4px',
            fontSize: '14px',
            color: 'var(--text-secondary)',
          }}
        >
          选择分析类型，提交代码或文件进行安全检测
        </p>
      </div>

      {/* Tab Switcher */}
      <div
        className="animate-slide-up"
        style={{
          marginBottom: '24px',
          display: 'flex',
          borderRadius: '12px',
          padding: '4px',
          background: 'rgba(148,163,184,0.06)',
          animationDelay: '60ms',
          animationFillMode: 'both',
        }}
      >
        <button
          onClick={() => setActiveTab('code')}
          style={{
            display: 'flex',
            flex: 1,
            alignItems: 'center',
            justifyContent: 'center',
            gap: '8px',
            borderRadius: '8px',
            padding: '12px 0',
            fontSize: '14px',
            fontWeight: 500,
            transition: 'all 0.2s',
            background:
              activeTab === 'code'
                ? 'var(--bg-card)'
                : 'transparent',
            color:
              activeTab === 'code'
                ? 'var(--accent-start)'
                : 'var(--text-secondary)',
            boxShadow:
              activeTab === 'code' ? 'var(--shadow-sm)' : 'none',
            border: 'none',
            cursor: 'pointer',
          }}
        >
          <Code2 size={16} />
          代码漏洞检测
        </button>
        <button
          onClick={() => setActiveTab('malware')}
          style={{
            display: 'flex',
            flex: 1,
            alignItems: 'center',
            justifyContent: 'center',
            gap: '8px',
            borderRadius: '8px',
            padding: '12px 0',
            fontSize: '14px',
            fontWeight: 500,
            transition: 'all 0.2s',
            background:
              activeTab === 'malware'
                ? 'var(--bg-card)'
                : 'transparent',
            color:
              activeTab === 'malware'
                ? 'var(--accent-start)'
                : 'var(--text-secondary)',
            boxShadow:
              activeTab === 'malware' ? 'var(--shadow-sm)' : 'none',
            border: 'none',
            cursor: 'pointer',
          }}
        >
          <Bug size={16} />
          恶意代码分析
        </button>
      </div>

      {/* Error Alert */}
      {error && (
        <div
          className="animate-slide-up"
          style={{
            marginBottom: '24px',
            display: 'flex',
            alignItems: 'center',
            gap: '12px',
            borderRadius: '16px',
            border: '1px solid var(--semantic-danger)',
            padding: '12px 16px',
            background: 'rgba(239,68,68,0.06)',
          }}
        >
          <AlertCircle size={18} style={{ color: 'var(--semantic-danger)', flexShrink: 0 }} />
          <span style={{ fontSize: '14px', color: 'var(--semantic-danger)' }}>
            {error}
          </span>
          <button
            onClick={() => setError(null)}
            style={{ marginLeft: 'auto', color: 'var(--semantic-danger)', background: 'none', border: 'none', cursor: 'pointer' }}
          >
            <X size={16} />
          </button>
        </div>
      )}

      {/* Success Indicator */}
      {success && (
        <div
          className="animate-slide-up"
          style={{
            marginBottom: '24px',
            display: 'flex',
            alignItems: 'center',
            gap: '12px',
            borderRadius: '16px',
            border: '1px solid #10B981',
            padding: '12px 16px',
            background: 'rgba(16,185,129,0.06)',
          }}
        >
          <CheckCircle2 size={18} style={{ color: '#10B981', flexShrink: 0 }} />
          <span style={{ fontSize: '14px', fontWeight: 500, color: '#10B981' }}>
            任务已创建，正在跳转到分析页面...
          </span>
        </div>
      )}

      {/* Content Area */}
      <div
        className="animate-slide-up"
        style={{ animationDelay: '120ms', animationFillMode: 'both' }}
      >
        {activeTab === 'code' ? (
          /* ─── Code Scan Tab ─────────────────────────── */
          <div style={{ display: 'grid', gridTemplateColumns: '3fr 2fr', gap: '24px' }}>
            {/* Left: Code Editor Area */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <div
                style={{
                  overflow: 'hidden',
                  borderRadius: '16px',
                  border: '1px solid var(--border-light)',
                  boxShadow: 'var(--shadow-sm)',
                }}
              >
                {/* Toolbar */}
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    borderBottom: '1px solid var(--border-light)',
                    padding: '12px 16px',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                    {/* Edit/Preview toggle */}
                    <div
                      style={{
                        display: 'flex',
                        borderRadius: '8px',
                        padding: '2px',
                        background: 'rgba(148,163,184,0.06)',
                      }}
                    >
                      <button
                        onClick={() => setCodeViewMode('edit')}
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: '6px',
                          borderRadius: '6px',
                          padding: '6px 12px',
                          fontSize: '12px',
                          fontWeight: 500,
                          transition: 'all 0.15s',
                          background:
                            codeViewMode === 'edit' ? 'white' : 'transparent',
                          color:
                            codeViewMode === 'edit'
                              ? 'var(--text-primary)'
                              : 'var(--text-secondary)',
                          boxShadow:
                            codeViewMode === 'edit'
                              ? 'var(--shadow-sm)'
                              : 'none',
                          border: 'none',
                          cursor: 'pointer',
                        }}
                      >
                        <Pencil size={11} />
                        编辑
                      </button>
                      <button
                        onClick={() => setCodeViewMode('preview')}
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: '6px',
                          borderRadius: '6px',
                          padding: '6px 12px',
                          fontSize: '12px',
                          fontWeight: 500,
                          transition: 'all 0.15s',
                          background:
                            codeViewMode === 'preview' ? 'white' : 'transparent',
                          color:
                            codeViewMode === 'preview'
                              ? 'var(--text-primary)'
                              : 'var(--text-secondary)',
                          boxShadow:
                            codeViewMode === 'preview'
                              ? 'var(--shadow-sm)'
                              : 'none',
                          border: 'none',
                          cursor: 'pointer',
                        }}
                      >
                        <Eye size={11} />
                        预览
                      </button>
                    </div>

                    {/* Input mode toggle */}
                    {codeViewMode === 'edit' && (
                      <div
                        style={{
                          display: 'flex',
                          borderRadius: '8px',
                          padding: '2px',
                          background: 'rgba(148,163,184,0.06)',
                        }}
                      >
                        <button
                          onClick={() => setInputMode('paste')}
                          style={{
                            borderRadius: '6px',
                            padding: '6px 12px',
                            fontSize: '12px',
                            fontWeight: 500,
                            transition: 'all 0.15s',
                            background:
                              inputMode === 'paste' ? 'white' : 'transparent',
                            color:
                              inputMode === 'paste'
                                ? 'var(--text-primary)'
                                : 'var(--text-secondary)',
                            boxShadow:
                              inputMode === 'paste'
                                ? 'var(--shadow-sm)'
                                : 'none',
                            border: 'none',
                            cursor: 'pointer',
                          }}
                        >
                          粘贴代码
                        </button>
                        <button
                          onClick={() => setInputMode('upload')}
                          style={{
                            borderRadius: '6px',
                            padding: '6px 12px',
                            fontSize: '12px',
                            fontWeight: 500,
                            transition: 'all 0.15s',
                            background:
                              inputMode === 'upload' ? 'white' : 'transparent',
                            color:
                              inputMode === 'upload'
                                ? 'var(--text-primary)'
                                : 'var(--text-secondary)',
                            boxShadow:
                              inputMode === 'upload'
                                ? 'var(--shadow-sm)'
                                : 'none',
                            border: 'none',
                            cursor: 'pointer',
                          }}
                        >
                          上传文件
                        </button>
                      </div>
                    )}
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <button
                      onClick={handleCopy}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '4px',
                        borderRadius: '8px',
                        padding: '6px 12px',
                        fontSize: '12px',
                        fontWeight: 500,
                        transition: 'color 0.15s',
                        color: 'var(--text-secondary)',
                        background: 'none',
                        border: 'none',
                        cursor: 'pointer',
                      }}
                      onMouseEnter={(e) => {
                        e.currentTarget.style.background = 'rgba(148,163,184,0.06)'
                      }}
                      onMouseLeave={(e) => {
                        e.currentTarget.style.background = 'transparent'
                      }}
                    >
                      {copied ? <Check size={12} /> : <Copy size={12} />}
                      {copied ? '已复制' : '复制'}
                    </button>
                  </div>
                </div>

                {/* Code Area */}
                {codeViewMode === 'edit' && inputMode === 'paste' ? (
                  <div style={{ display: 'flex', position: 'relative' }}>
                    {/* Line Numbers */}
                    <div
                      className="custom-scrollbar"
                      style={{
                        flexShrink: 0,
                        userSelect: 'none',
                        overflow: 'hidden',
                        padding: '12px 8px 12px 12px',
                        textAlign: 'right',
                        fontFamily: "'JetBrains Mono', 'Fira Code', 'Cascadia Code', Consolas, monospace",
                        fontSize: '12px',
                        lineHeight: '1.625',
                        color: 'var(--text-muted)',
                        background: 'rgba(148,163,184,0.03)',
                        minWidth: '40px',
                      }}
                    >
                      {code.split('\n').map((_, i) => (
                        <div key={i}>{i + 1}</div>
                      ))}
                    </div>
                    {/* Textarea */}
                    <textarea
                      value={code}
                      onChange={(e) => {
                        setCode(e.target.value)
                        if (error) setError(null)
                      }}
                      className="custom-scrollbar"
                      style={{
                        width: '100%',
                        resize: 'none',
                        background: 'var(--bg-card)',
                        padding: '12px 16px',
                        fontSize: '14px',
                        lineHeight: '1.625',
                        minHeight: '280px',
                        fontFamily:
                          "'JetBrains Mono', 'Fira Code', 'Cascadia Code', Consolas, monospace",
                        color: 'var(--text-primary)',
                        border: 'none',
                        outline: 'none',
                      }}
                      placeholder="在此粘贴需要检测的代码..."
                      spellCheck={false}
                    />
                  </div>
                ) : codeViewMode === 'preview' ? (
                  /* ─── Syntax Highlighted Preview ────────── */
                  <div className="code-block-dark" style={{ borderRadius: '0 0 16px 16px' }}>
                    <div className="code-header">
                      <div className="code-dot" style={{ background: '#EF4444' }} />
                      <div className="code-dot" style={{ background: '#F59E0B' }} />
                      <div className="code-dot" style={{ background: '#10B981' }} />
                      <span style={{ marginLeft: '8px' }}>{languages.find(l => l.value === language)?.label || language}</span>
                    </div>
                    <pre
                      className="custom-scrollbar"
                      style={{
                        padding: '12px 16px',
                        margin: 0,
                        minHeight: '280px',
                        maxHeight: '500px',
                        overflowX: 'auto',
                      }}
                    >
                      <code>
                        {code.split('\n').map((line, lineIdx) => (
                          <div key={lineIdx} style={{ display: 'flex' }}>
                            <span
                              style={{
                                display: 'inline-block',
                                width: '36px',
                                textAlign: 'right',
                                marginRight: '16px',
                                color: '#4A5568',
                                fontSize: '12px',
                                userSelect: 'none',
                                flexShrink: 0,
                              }}
                            >
                              {lineIdx + 1}
                            </span>
                            <span>
                              {highlightLine(line, language).map((token, tokenIdx) => (
                                <span
                                  key={tokenIdx}
                                  style={{
                                    color: TOKEN_COLORS[token.type] || TOKEN_COLORS.normal,
                                    fontWeight: token.type === 'keyword' ? 600 : 400,
                                    fontStyle: token.type === 'comment' ? 'italic' : 'normal',
                                  }}
                                >
                                  {token.text}
                                </span>
                              ))}
                            </span>
                          </div>
                        ))}
                      </code>
                    </pre>
                  </div>
                ) : (
                  <div
                    style={{
                      display: 'flex',
                      flexDirection: 'column',
                      alignItems: 'center',
                      justifyContent: 'center',
                      padding: '48px',
                      minHeight: '280px',
                    }}
                  >
                    <Upload
                      size={40}
                      style={{ color: 'var(--text-muted)' }}
                    />
                    <p
                      style={{
                        marginTop: '12px',
                        fontWeight: 500,
                        fontSize: '14px',
                        color: 'var(--text-secondary)',
                      }}
                    >
                      拖拽代码文件到此处
                    </p>
                    <p
                      style={{
                        marginTop: '4px',
                        fontSize: '12px',
                        color: 'var(--text-muted)',
                      }}
                    >
                      支持 .py, .js, .java, .go, .c, .rs 文件
                    </p>
                    <label
                      style={{
                        marginTop: '16px',
                        cursor: 'pointer',
                        borderRadius: '12px',
                        padding: '10px 20px',
                        fontSize: '14px',
                        fontWeight: 500,
                        background: 'rgba(91,163,255,0.06)',
                        color: 'var(--accent-start)',
                      }}
                    >
                      浏览文件
                      <input
                        type="file"
                        accept=".py,.js,.java,.go,.c,.cpp,.rs,.ts"
                        style={{ display: 'none' }}
                        onChange={(e) => {
                          const file = e.target.files?.[0]
                          if (file) {
                            const reader = new FileReader()
                            reader.onload = (ev) => {
                              setCode(ev.target?.result as string)
                              setInputMode('paste')
                            }
                            reader.readAsText(file)
                          }
                        }}
                      />
                    </label>
                  </div>
                )}
              </div>

              {/* Task Name Input */}
              <div
                className="animate-slide-up"
                style={{
                  borderRadius: '16px',
                  border: '1px solid var(--border-light)',
                  background: 'var(--bg-card)',
                  padding: '16px',
                  boxShadow: 'var(--shadow-sm)',
                }}
              >
                <label
                  style={{
                    display: 'block',
                    marginBottom: '8px',
                    fontSize: '12px',
                    fontWeight: 500,
                    color: 'var(--text-secondary)',
                  }}
                >
                  任务名称
                </label>
                <input
                  type="text"
                  value={taskName}
                  onChange={(e) => {
                    setTaskName(e.target.value)
                    if (error) setError(null)
                  }}
                  placeholder={deriveTaskName()}
                  style={{
                    width: '100%',
                    borderRadius: '12px',
                    border: '1px solid var(--border-normal)',
                    background: 'var(--bg-card)',
                    padding: '10px 16px',
                    fontSize: '14px',
                    color: 'var(--text-primary)',
                    outline: 'none',
                  }}
                />
                <p
                  style={{
                    marginTop: '6px',
                    fontSize: '12px',
                    color: 'var(--text-muted)',
                  }}
                >
                  留空将自动从代码内容生成
                </p>
              </div>
            </div>

            {/* Right: Settings Panel */}
            <div>
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
                    marginBottom: '20px',
                    fontWeight: 600,
                    fontSize: '16px',
                    color: 'var(--text-primary)',
                  }}
                >
                  检测配置
                </h3>

                {/* Language Selector */}
                <div style={{ marginBottom: '20px' }}>
                  <label
                    style={{
                      display: 'block',
                      marginBottom: '8px',
                      fontSize: '12px',
                      fontWeight: 500,
                      color: 'var(--text-secondary)',
                    }}
                  >
                    编程语言
                  </label>
                  <div style={{ position: 'relative' }}>
                    <select
                      value={language}
                      onChange={(e) => setLanguage(e.target.value)}
                      style={{
                        width: '100%',
                        appearance: 'none',
                        borderRadius: '12px',
                        border: '1px solid var(--border-normal)',
                        background: 'var(--bg-card)',
                        padding: '12px 16px',
                        fontSize: '14px',
                        color: 'var(--text-primary)',
                        outline: 'none',
                        cursor: 'pointer',
                      }}
                    >
                      {languages.map((lang) => (
                        <option key={lang.value} value={lang.value}>
                          {lang.label}
                        </option>
                      ))}
                    </select>
                    <ChevronDown
                      size={16}
                      style={{
                        position: 'absolute',
                        right: '12px',
                        top: '50%',
                        transform: 'translateY(-50%)',
                        color: 'var(--text-muted)',
                        pointerEvents: 'none',
                      }}
                    />
                  </div>
                </div>

                {/* Scan Options */}
                <div style={{ marginBottom: '20px' }}>
                  <label
                    style={{
                      display: 'block',
                      marginBottom: '8px',
                      fontSize: '12px',
                      fontWeight: 500,
                      color: 'var(--text-secondary)',
                    }}
                  >
                    扫描范围
                  </label>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '8px 16px' }}>
                    {[
                      { label: 'SQL 注入检测', checked: true },
                      { label: 'XSS 跨站脚本', checked: true },
                      { label: '命令注入检测', checked: true },
                      { label: '路径遍历检测', checked: false },
                      { label: '硬编码密钥检测', checked: false },
                    ].map((opt) => (
                      <label
                        key={opt.label}
                        style={{ display: 'flex', alignItems: 'center', gap: '10px', cursor: 'pointer' }}
                      >
                        <input
                          type="checkbox"
                          defaultChecked={opt.checked}
                          style={{ height: '16px', width: '16px', borderRadius: '4px', accentColor: '#5BA3FF' }}
                        />
                        <span
                          style={{ fontSize: '14px', color: 'var(--text-primary)' }}
                        >
                          {opt.label}
                        </span>
                      </label>
                    ))}
                  </div>
                </div>

                {/* Enhanced Code Stats */}
                <div
                  style={{
                    marginBottom: '20px',
                    borderRadius: '12px',
                    padding: '16px',
                    background: 'rgba(148,163,184,0.04)',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
                    <BarChart3 size={14} style={{ color: 'var(--accent-start)' }} />
                    <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)' }}>
                      代码统计
                    </span>
                  </div>

                  {/* Line count */}
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '12px', marginBottom: '4px' }}>
                        <span style={{ color: 'var(--text-secondary)' }}>代码行数</span>
                        <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                          {codeStats.lineCount}
                        </span>
                      </div>
                      <div style={{ height: '6px', borderRadius: '9999px', overflow: 'hidden', background: 'rgba(148,163,184,0.08)' }}>
                        <div
                          style={{
                            height: '100%',
                            borderRadius: '9999px',
                            transition: 'all 0.3s',
                            width: `${Math.min(100, (codeStats.lineCount / 100) * 100)}%`,
                            background: 'var(--accent-gradient)',
                          }}
                        />
                      </div>
                    </div>

                    {/* Non-empty lines */}
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '12px', marginBottom: '4px' }}>
                        <span style={{ color: 'var(--text-secondary)' }}>非空行</span>
                        <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                          {codeStats.nonEmptyCount}
                        </span>
                      </div>
                      <div style={{ height: '6px', borderRadius: '9999px', overflow: 'hidden', background: 'rgba(148,163,184,0.08)' }}>
                        <div
                          style={{
                            height: '100%',
                            borderRadius: '9999px',
                            transition: 'all 0.3s',
                            width: codeStats.lineCount > 0 ? `${(codeStats.nonEmptyCount / codeStats.lineCount) * 100}%` : '0%',
                            background: 'linear-gradient(90deg, #10B981, #5EEAD4)',
                          }}
                        />
                      </div>
                    </div>

                    {/* Character count */}
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '12px', marginBottom: '4px' }}>
                        <span style={{ color: 'var(--text-secondary)' }}>字符数</span>
                        <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                          {codeStats.charCount.toLocaleString()}
                        </span>
                      </div>
                      <div style={{ height: '6px', borderRadius: '9999px', overflow: 'hidden', background: 'rgba(148,163,184,0.08)' }}>
                        <div
                          style={{
                            height: '100%',
                            borderRadius: '9999px',
                            transition: 'all 0.3s',
                            width: `${Math.min(100, (codeStats.charCount / 2000) * 100)}%`,
                            background: 'linear-gradient(90deg, #5BA3FF, #5EEAD4)',
                          }}
                        />
                      </div>
                    </div>

                    {/* Separator */}
                    <div style={{ paddingTop: '4px', borderTop: '1px solid var(--border-light)' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                        <Layers size={12} style={{ color: codeStats.complexity.levelColor }} />
                        <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)' }}>
                          复杂度估算
                        </span>
                        <span
                          style={{
                            marginLeft: 'auto',
                            fontSize: '11px',
                            fontWeight: 700,
                            padding: '2px 6px',
                            borderRadius: '4px',
                            color: codeStats.complexity.levelColor,
                            background: `${codeStats.complexity.levelColor}15`,
                          }}
                        >
                          {codeStats.complexity.level}
                        </span>
                      </div>
                      <div style={{ height: '8px', borderRadius: '9999px', overflow: 'hidden', background: 'rgba(148,163,184,0.08)' }}>
                        <div
                          style={{
                            height: '100%',
                            borderRadius: '9999px',
                            transition: 'all 0.3s',
                            width: `${codeStats.complexity.score}%`,
                            background: `linear-gradient(90deg, #10B981, ${codeStats.complexity.levelColor})`,
                          }}
                        />
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginTop: '8px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                          <Code2 size={10} style={{ color: 'var(--text-muted)' }} />
                          <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>
                            {codeStats.complexity.funcCount} 函数
                          </span>
                        </div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                          <GitBranch size={10} style={{ color: 'var(--text-muted)' }} />
                          <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>
                            {codeStats.complexity.maxNesting} 层嵌套
                          </span>
                        </div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                          <Layers size={10} style={{ color: 'var(--text-muted)' }} />
                          <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>
                            {codeStats.complexity.condCount} 分支
                          </span>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Submit Button */}
                <button
                  onClick={handleSubmit}
                  disabled={isSubmitting || !code.trim()}
                  className="btn-shimmer gradient-bg"
                  style={{
                    display: 'flex',
                    width: '100%',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: '8px',
                    borderRadius: '12px',
                    padding: '12px 0',
                    fontSize: '14px',
                    fontWeight: 500,
                    color: 'white',
                    transition: 'all 0.15s',
                    boxShadow: !isSubmitting ? 'var(--shadow-brand)' : 'none',
                    opacity: isSubmitting || !code.trim() ? 0.5 : 1,
                    border: 'none',
                    cursor: isSubmitting || !code.trim() ? 'not-allowed' : 'pointer',
                  }}
                >
                  {isSubmitting ? (
                    <>
                      <div
                        style={{
                          height: '16px',
                          width: '16px',
                          borderRadius: '50%',
                          border: '2px solid white',
                          borderTopColor: 'transparent',
                          animation: 'spin 1s linear infinite',
                        }}
                      />
                      提交中...
                    </>
                  ) : (
                    <>
                      <Play size={16} />
                      开始代码扫描
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>
        ) : (
          /* ─── Malware Analysis Tab ──────────────────── */
          <div style={{ display: 'grid', gridTemplateColumns: '3fr 2fr', gap: '24px' }}>
            {/* Left: Upload Area */}
            <div>
              <div
                style={{
                  overflow: 'hidden',
                  borderRadius: '16px',
                  border: '1px solid var(--border-light)',
                  background: 'var(--bg-card)',
                  boxShadow: 'var(--shadow-sm)',
                }}
              >
                {/* Drop Zone */}
                <div
                  className={isDragOver ? 'drag-active' : ''}
                  style={{
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'center',
                    justifyContent: 'center',
                    padding: '48px',
                    minHeight: '280px',
                    border: isDragOver ? undefined : '2px dashed var(--border-normal)',
                    borderRadius: '16px',
                    transition: 'all 0.2s',
                  }}
                  onDragOver={(e) => {
                    e.preventDefault()
                    setIsDragOver(true)
                  }}
                  onDragLeave={() => setIsDragOver(false)}
                  onDrop={handleFileDrop}
                >
                  <div
                    style={{
                      marginBottom: '16px',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      borderRadius: '16px',
                      width: '72px',
                      height: '72px',
                      background: 'rgba(91,163,255,0.06)',
                    }}
                  >
                    <Upload size={32} style={{ color: '#5BA3FF' }} />
                  </div>
                  <p
                    style={{
                      fontWeight: 500,
                      fontSize: '16px',
                      color: 'var(--text-primary)',
                    }}
                  >
                    拖拽文件到此处上传
                  </p>
                  <p
                    style={{
                      marginTop: '8px',
                      fontSize: '13px',
                      color: 'var(--text-secondary)',
                    }}
                  >
                    或点击下方按钮选择文件
                  </p>
                  <p
                    style={{
                      marginTop: '4px',
                      fontSize: '12px',
                      color: 'var(--text-muted)',
                    }}
                  >
                    支持 PE、Office 文档、脚本文件等，最大 50MB
                  </p>
                  <label
                    className="gradient-bg"
                    style={{
                      marginTop: '24px',
                      cursor: 'pointer',
                      borderRadius: '12px',
                      padding: '10px 24px',
                      fontSize: '14px',
                      fontWeight: 500,
                      color: 'white',
                      boxShadow: 'var(--shadow-brand)',
                    }}
                  >
                    选择文件
                    <input
                      type="file"
                      accept=".exe,.dll,.doc,.docm,.xls,.xlsm,.ppt,.pptm,.pdf,.py,.js,.vbs,.ps1,.bat,.sh"
                      multiple
                      style={{ display: 'none' }}
                      onChange={handleFileSelect}
                    />
                  </label>
                </div>
              </div>
            </div>

            {/* Right: File List & Config */}
            <div>
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
                    marginBottom: '20px',
                    fontWeight: 600,
                    fontSize: '16px',
                    color: 'var(--text-primary)',
                  }}
                >
                  已上传文件
                </h3>

                {uploadedFiles.length === 0 ? (
                  <div
                    style={{
                      display: 'flex',
                      flexDirection: 'column',
                      alignItems: 'center',
                      justifyContent: 'center',
                      padding: '40px 0',
                      color: 'var(--text-muted)',
                    }}
                  >
                    <FileText size={32} style={{ marginBottom: '8px', opacity: 0.4 }} />
                    <p style={{ fontSize: '12px' }}>暂无文件</p>
                  </div>
                ) : (
                  <div className="custom-scrollbar" style={{ maxHeight: '240px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '12px' }}>
                    {uploadedFiles.map((file, index) => (
                      <div
                        key={`${file.name}-${index}`}
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: '12px',
                          borderRadius: '12px',
                          border: '1px solid var(--border-light)',
                          padding: '12px',
                        }}
                      >
                        <div
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            borderRadius: '8px',
                            width: '36px',
                            height: '36px',
                            background: 'rgba(239,68,68,0.08)',
                            flexShrink: 0,
                          }}
                        >
                          <FileText size={16} style={{ color: '#EF4444' }} />
                        </div>
                        <div style={{ flex: 1, minWidth: 0 }}>
                          <div
                            style={{
                              overflow: 'hidden',
                              textOverflow: 'ellipsis',
                              whiteSpace: 'nowrap',
                              fontSize: '14px',
                              fontWeight: 500,
                              color: 'var(--text-primary)',
                            }}
                          >
                            {file.name}
                          </div>
                          <div
                            style={{ fontSize: '12px', color: 'var(--text-muted)' }}
                          >
                            {formatFileSize(file.size)}
                          </div>
                        </div>
                        <button
                          onClick={() => removeFile(index)}
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            borderRadius: '8px',
                            padding: '4px',
                            transition: 'color 0.15s',
                            color: 'var(--text-muted)',
                            background: 'none',
                            border: 'none',
                            cursor: 'pointer',
                          }}
                          onMouseEnter={(e) => {
                            e.currentTarget.style.color = '#EF4444'
                          }}
                          onMouseLeave={(e) => {
                            e.currentTarget.style.color = 'var(--text-muted)'
                          }}
                        >
                          <X size={14} />
                        </button>
                      </div>
                    ))}
                  </div>
                )}

                {/* Analysis Options */}
                <div style={{ marginTop: '24px', borderTop: '1px solid var(--border-light)', paddingTop: '20px' }}>
                  <h4
                    style={{
                      marginBottom: '12px',
                      fontSize: '12px',
                      fontWeight: 500,
                      color: 'var(--text-secondary)',
                    }}
                  >
                    分析选项
                  </h4>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '8px 16px' }}>
                    {[
                      { label: '文件特征提取', checked: true },
                      { label: 'IOC 指标提取', checked: true },
                      { label: 'YARA 规则匹配', checked: true },
                      { label: 'ATT&CK 技术映射', checked: false },
                    ].map((opt) => (
                      <label
                        key={opt.label}
                        style={{ display: 'flex', alignItems: 'center', gap: '10px', cursor: 'pointer' }}
                      >
                        <input
                          type="checkbox"
                          defaultChecked={opt.checked}
                          style={{ height: '16px', width: '16px', borderRadius: '4px', accentColor: '#5EEAD4' }}
                        />
                        <span
                          style={{ fontSize: '14px', color: 'var(--text-primary)' }}
                        >
                          {opt.label}
                        </span>
                      </label>
                    ))}
                  </div>
                </div>

                {/* Submit Button */}
                <button
                  onClick={handleSubmit}
                  disabled={isSubmitting || uploadedFiles.length === 0}
                  className="btn-shimmer"
                  style={{
                    marginTop: '24px',
                    display: 'flex',
                    width: '100%',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: '8px',
                    borderRadius: '12px',
                    padding: '12px 0',
                    fontSize: '14px',
                    fontWeight: 500,
                    color: 'white',
                    transition: 'all 0.15s',
                    background:
                      'linear-gradient(135deg, #5EEAD4 0%, #10B981 100%)',
                    boxShadow:
                      !isSubmitting
                        ? '0 8px 32px rgba(94,234,212,0.25)'
                        : 'none',
                    opacity: isSubmitting || uploadedFiles.length === 0 ? 0.5 : 1,
                    border: 'none',
                    cursor: isSubmitting || uploadedFiles.length === 0 ? 'not-allowed' : 'pointer',
                  }}
                >
                  {isSubmitting ? (
                    <>
                      <div style={{
                        height: '16px',
                        width: '16px',
                        borderRadius: '50%',
                        border: '2px solid white',
                        borderTopColor: 'transparent',
                        animation: 'spin 1s linear infinite',
                      }} />
                      提交中...
                    </>
                  ) : (
                    <>
                      <Play size={16} />
                      开始恶意分析
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

export default Submit;
