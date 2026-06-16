import { useState, useEffect, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { Spin } from 'antd';
import {
  Brain,
  Wrench,
  Eye,
  CheckCircle2,
  XCircle,
  ChevronDown,
  ChevronUp,
  FileText,
  Loader2,
  ArrowRight,
} from 'lucide-react';
import { getTask, getTaskSteps } from '@/services/api';
import type { TaskResponse, AnalysisStep } from '@/services/api';
import { useWebSocket, normalizeWSMessage } from '@/hooks/useWebSocket';
import type { WSMessage } from '@/hooks/useWebSocket';

// ─── Types ──────────────────────────────────────────
type StepType = 'thought' | 'action' | 'observation' | 'done' | 'error';

interface DisplayStep {
  id: string;
  type: StepType;
  title: string;
  content: string;
  detail?: string;
  timestamp: string;
}

// ─── localStorage helpers for active task ───────────
const ACTIVE_TASK_KEY = 'secagent_active_task';

function saveActiveTask(taskId: string) {
  localStorage.setItem(ACTIVE_TASK_KEY, taskId);
}

function getActiveTask(): string | null {
  return localStorage.getItem(ACTIVE_TASK_KEY);
}

function clearActiveTask() {
  localStorage.removeItem(ACTIVE_TASK_KEY);
}

// ─── Step Config ────────────────────────────────────
const stepConfig: Record<
  StepType,
  {
    icon: typeof Brain;
    label: string;
    color: string;
    bgColor: string;
    borderColor: string;
  }
> = {
  thought: {
    icon: Brain,
    label: 'Thought',
    color: '#5BA3FF',
    bgColor: 'rgba(91,163,255,0.06)',
    borderColor: 'rgba(91,163,255,0.2)',
  },
  action: {
    icon: Wrench,
    label: 'Action',
    color: '#F59E0B',
    bgColor: 'rgba(245,158,11,0.06)',
    borderColor: 'rgba(245,158,11,0.2)',
  },
  observation: {
    icon: Eye,
    label: 'Observation',
    color: '#10B981',
    bgColor: 'rgba(16,185,129,0.06)',
    borderColor: 'rgba(16,185,129,0.2)',
  },
  done: {
    icon: CheckCircle2,
    label: 'Done',
    color: '#5BA3FF',
    bgColor: 'rgba(91,163,255,0.06)',
    borderColor: 'rgba(91,163,255,0.3)',
  },
  error: {
    icon: XCircle,
    label: 'Error',
    color: '#EF4444',
    bgColor: 'rgba(239,68,68,0.06)',
    borderColor: 'rgba(239,68,68,0.2)',
  },
};

// ─── Type label mapping ─────────────────────────────
const typeLabels: Record<string, string> = {
  vulnerability_detection: '代码漏洞检测',
  malware_analysis: '恶意代码分析',
};

// ─── Tool name / message cleanup ────────────────────
/** 清理工具名中的路径前缀，如 "semgrep/bandit" → "bandit" */
function cleanToolName(name: string): string {
  const parts = name.split('/');
  return parts[parts.length - 1];
}

/** 清理消息文本中的工具路径引用，如 "semgrep/bandit" → "bandit" */
function cleanMessageText(text: string): string {
  return text.replace(/\b[\w-]+\/([\w-]+)\b/g, '$1');
}

// ─── Recursive JSON formatter ───────────────────────
/**
 * 递归格式化 JSON 数据为可读文本，提取所有嵌套 JSON 对象，
 * 每一类数据换行展示，不显示原始 JSON 格式
 */
function formatJsonRecursive(
  data: unknown,
  indent = 0,
  prefix = '',
): string {
  const pad = '  '.repeat(indent);

  if (data === null || data === undefined) return '';

  if (typeof data !== 'object') {
    return `${pad}${prefix}${String(data)}`;
  }

  const lines: string[] = [];

  if (Array.isArray(data)) {
    for (let i = 0; i < data.length; i++) {
      const item = data[i];
      if (typeof item === 'object' && item !== null && !Array.isArray(item)) {
        const objLines = formatJsonRecursive(item, indent, `${prefix}▸ [${i + 1}] `);
        lines.push(objLines);
      } else {
        lines.push(`${pad}${prefix}[${i + 1}] ${String(item)}`);
      }
    }
    return lines.join('\n');
  }

  const obj = data as Record<string, unknown>;
  for (const [key, val] of Object.entries(obj)) {
    const label = prefix ? `${prefix}${key}: ` : `${key}: `;

    if (val === null || val === undefined) {
      lines.push(`${pad}${label}-`);
    } else if (typeof val === 'string') {
      // 短字符串直接显示
      if (val.length < 80 && !val.includes('{')) {
        lines.push(`${pad}${label}${val}`);
      } else if (val.includes('{')) {
        // 字符串中包含嵌套 JSON，递归解析
        try {
          const innerStart = val.indexOf('{');
          const innerEnd = val.lastIndexOf('}') + 1;
          if (innerStart >= 0 && innerEnd > innerStart) {
            const before = val.slice(0, innerStart).trim();
            const jsonPart = val.slice(innerStart, innerEnd);
            const after = val.slice(innerEnd).trim();
            const parsed = JSON.parse(jsonPart);
            if (before) lines.push(`${pad}${label}${before}`);
            lines.push(formatJsonRecursive(parsed, indent + 1));
            if (after) lines.push(`${pad}${after}`);
          } else {
            const truncated = val.length > 200 ? val.slice(0, 200) + '...' : val;
            lines.push(`${pad}${label}${truncated}`);
          }
        } catch {
          const truncated = val.length > 200 ? val.slice(0, 200) + '...' : val;
          lines.push(`${pad}${label}${truncated}`);
        }
      } else {
        const truncated = val.length > 200 ? val.slice(0, 200) + '...' : val;
        lines.push(`${pad}${label}${truncated}`);
      }
    } else if (typeof val === 'object') {
      if (Array.isArray(val) && val.length > 0) {
        lines.push(`${pad}${label}`);
        lines.push(formatJsonRecursive(val, indent + 1));
      } else if (Object.keys(val as object).length > 0) {
        lines.push(`${pad}${label}`);
        lines.push(formatJsonRecursive(val, indent + 1));
      } else {
        lines.push(`${pad}${label}{}`);
      }
    } else {
      lines.push(`${pad}${label}${String(val)}`);
    }
  }

  return lines.join('\n');
}

// ─── Shared step parser ─────────────────────────────
/**
 * 将后端存储的原始 step 数据（JSON 字符串）解析为 DisplayStep
 * 同时用于 WebSocket 路径和 HTTP 轮询路径
 */
function parseStepFromRaw(
  stepType: StepType,
  rawContent: string,
  stepId: string,
  createdAt: string,
): DisplayStep {
  let title = '';
  let content = rawContent;
  let detail: string | undefined;

  switch (stepType) {
    case 'thought': {
      title = '思考';
      try {
        const parsed = JSON.parse(rawContent);
        // 当 content 为空时，不显示原始 JSON，由 detail 区域展示关键信息
        content = parsed.content ?? '';
        if (parsed.tool_calls_requested && Array.isArray(parsed.tool_calls_requested) && parsed.tool_calls_requested.length > 0) {
          detail = `请求工具: ${parsed.tool_calls_requested.join(', ')}`;
        }
        if (parsed.finish_reason) {
          detail = detail ? `${detail}\n结束原因: ${parsed.finish_reason}` : `结束原因: ${parsed.finish_reason}`;
        }
      } catch {
        // 非 JSON 字符串，直接使用
      }
      break;
    }
    case 'action': {
      title = '执行操作';
      try {
        const parsed = JSON.parse(rawContent);
        const results = parsed.results as Array<{
          name: string; ok: boolean; args?: Record<string, unknown>;
          findings_count?: number; iocs_count?: number; results_count?: number;
          techniques_count?: number; matches_count?: number;
          result_preview?: string; message?: string; status?: string; error?: string;
        }> | undefined;
        if (results && results.length > 0) {
          content = results.map(r => {
            const displayName = cleanToolName(r.name);
            let line = `${displayName}(${r.ok ? '成功' : '失败'})`;
            if (r.findings_count !== undefined) line += ` - 发现 ${r.findings_count} 个漏洞`;
            else if (r.iocs_count !== undefined) line += ` - 提取 ${r.iocs_count} 个 IOC`;
            else if (r.results_count !== undefined) line += ` - ${r.results_count} 条结果`;
            else if (r.techniques_count !== undefined) line += ` - ${r.techniques_count} 项技术`;
            else if (r.matches_count !== undefined) line += ` - ${r.matches_count} 条匹配`;
            else if (r.message) line += ` - ${cleanMessageText(r.message)}`;
            else if (r.error) line += ` - 错误: ${cleanMessageText(r.error)}`;
            return line;
          }).join(', ');
          // 使用递归 JSON 格式化生成详情
          const detailLines: string[] = [];
          for (const r of results) {
            const displayName = cleanToolName(r.name);
            detailLines.push(`▸ 工具: ${displayName}  [${r.ok ? '成功' : '失败'}]`);
            // 显示参数摘要（跳过 code 等超长字段）
            if (r.args) {
              for (const [key, val] of Object.entries(r.args)) {
                const valStr = String(val);
                if (valStr.length > 100) {
                  detailLines.push(`  参数 ${key}: ${valStr.slice(0, 100)}...`);
                } else {
                  detailLines.push(`  参数 ${key}: ${valStr}`);
                }
              }
            }
            if (r.status && r.status !== 'ok') detailLines.push(`  状态: ${r.status}`);
            if (r.message) detailLines.push(`  消息: ${cleanMessageText(r.message)}`);
            if (r.error) detailLines.push(`  错误: ${cleanMessageText(r.error)}`);
            if (r.findings_count !== undefined) detailLines.push(`  发现漏洞: ${r.findings_count} 个`);
            if (r.iocs_count !== undefined) detailLines.push(`  提取 IOC: ${r.iocs_count} 个`);
            if (r.results_count !== undefined) detailLines.push(`  结果数: ${r.results_count} 条`);
            if (r.techniques_count !== undefined) detailLines.push(`  ATT&CK 技术: ${r.techniques_count} 项`);
            if (r.matches_count !== undefined) detailLines.push(`  YARA 匹配: ${r.matches_count} 条`);

            // 递归格式化 result_preview / result_full 中的嵌套 JSON
            const resultData = r.result_preview;
            if (resultData) {
              try {
                const parsedResult = JSON.parse(resultData);
                const formatted = formatJsonRecursive(parsedResult, 1);
                if (formatted) detailLines.push(`  结果详情:\n${formatted}`);
              } catch {
                // 非 JSON，直接显示
                const truncated = resultData.length > 200 ? resultData.slice(0, 200) + '...' : resultData;
                detailLines.push(`  结果: ${cleanMessageText(truncated)}`);
              }
            }
          }
          detail = detailLines.join('\n');
        } else {
          content = rawContent;
        }
      } catch {
        content = rawContent;
      }
      break;
    }
    case 'observation': {
      title = '观察结果';
      try {
        const parsed = JSON.parse(rawContent);
        const observations = parsed.observations as Array<{
          tool: string; result_preview: string; result_full?: string;
          findings_count?: number; iocs_count?: number; results_count?: number;
          techniques_count?: number; matches_count?: number;
        }> | undefined;
        if (observations && observations.length > 0) {
          content = observations.map(o => {
            const displayName = cleanToolName(o.tool);
            let line = `${displayName}`;
            if (o.findings_count !== undefined) line += `: 发现 ${o.findings_count} 个漏洞`;
            else if (o.iocs_count !== undefined) line += `: 提取 ${o.iocs_count} 个 IOC`;
            else if (o.results_count !== undefined) line += `: ${o.results_count} 条结果`;
            else if (o.techniques_count !== undefined) line += `: ${o.techniques_count} 项 ATT&CK 技术`;
            else if (o.matches_count !== undefined) line += `: ${o.matches_count} 条 YARA 匹配`;
            else {
              // 尝试解析 result_preview 中的 JSON，提取 message 等可读字段
              let preview = o.result_preview;
              try {
                const parsed = JSON.parse(preview);
                preview = parsed.message || parsed.summary || preview;
              } catch {
                // 非 JSON，直接使用
              }
              line += `: ${cleanMessageText(preview)}`;
            }
            return line;
          }).join('\n');
          // 使用递归 JSON 格式化生成详情
          const detailLines: string[] = [];
          for (const o of observations) {
            const displayName = cleanToolName(o.tool);
            detailLines.push(`▸ 工具: ${displayName}`);
            if (o.findings_count !== undefined) detailLines.push(`  发现漏洞: ${o.findings_count} 个`);
            if (o.iocs_count !== undefined) detailLines.push(`  提取 IOC: ${o.iocs_count} 个`);
            if (o.results_count !== undefined) detailLines.push(`  结果数: ${o.results_count} 条`);
            if (o.techniques_count !== undefined) detailLines.push(`  ATT&CK 技术: ${o.techniques_count} 项`);
            if (o.matches_count !== undefined) detailLines.push(`  YARA 匹配: ${o.matches_count} 条`);
            // 递归格式化 result_preview/result_full
            const resultData = o.result_full || o.result_preview;
            if (resultData) {
              try {
                const parsed = JSON.parse(resultData);
                const formatted = formatJsonRecursive(parsed, 1);
                if (formatted) detailLines.push(`  结果详情:\n${formatted}`);
              } catch {
                const preview = resultData.length > 200 ? resultData.slice(0, 200) + '...' : resultData;
                detailLines.push(`  结果: ${cleanMessageText(preview)}`);
              }
            }
          }
          detail = detailLines.join('\n');
        } else {
          content = rawContent;
        }
      } catch {
        content = rawContent;
      }
      break;
    }
    default:
      title = stepType;
  }

  return {
    id: stepId,
    type: stepType,
    title,
    content,
    detail,
    timestamp: new Date(createdAt).toLocaleTimeString('zh-CN', {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    }),
  };
}

// ─── Component ──────────────────────────────────────
const Analysis = () => {
  const { taskId } = useParams<{ taskId: string }>();
  const navigate = useNavigate();
  const [steps, setSteps] = useState<DisplayStep[]>([]);
  const [expandedSteps, setExpandedSteps] = useState<Set<string>>(new Set());
  const [isAnalyzing, setIsAnalyzing] = useState(true);
  const [taskInfo, setTaskInfo] = useState<{ type: string; name: string } | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [taskNotFound, setTaskNotFound] = useState(false);
  const [totalSteps, setTotalSteps] = useState(8);

  // WebSocket message handler
  const handleWsMessage = useCallback(
    (msg: WSMessage) => {
      if (!taskId) return;

      // 规范化消息：解析可能是 JSON 字符串的字段
      const normalizedMsg = normalizeWSMessage(msg);
      const data = normalizedMsg.data;

      if (msg.type === 'thought' || msg.type === 'action' || msg.type === 'observation' || msg.type === 'done' || msg.type === 'error') {
        // 后端发送 step_num（snake_case），兼容两种格式
        const stepNum = (data.step_num ?? data.stepNum) as number;

        // 根据消息类型提取 title / content / detail
        let title = '';
        let content = '';
        let detail: string | undefined;

        switch (msg.type) {
          case 'thought':
            title = '思考';
            content = (data.content as string) ?? '';
            if (data.tool_calls_requested && (data.tool_calls_requested as string[]).length > 0) {
              detail = `请求工具: ${(data.tool_calls_requested as string[]).join(', ')}`;
            }
            if (data.finish_reason) {
              detail = detail ? `${detail}\n结束原因: ${data.finish_reason}` : `结束原因: ${data.finish_reason}`;
            }
            break;
          case 'action': {
            title = '执行操作';
            const results = data.results as Array<{ name: string; ok: boolean; args?: Record<string, unknown>; findings_count?: number; iocs_count?: number; results_count?: number; techniques_count?: number; matches_count?: number; result_preview?: string; message?: string; status?: string; error?: string }> | undefined;
            if (results && results.length > 0) {
              content = results.map(r => {
                const displayName = cleanToolName(r.name);
                let line = `${displayName}(${r.ok ? '成功' : '失败'})`;
                if (r.findings_count !== undefined) line += ` - 发现 ${r.findings_count} 个漏洞`;
                else if (r.iocs_count !== undefined) line += ` - 提取 ${r.iocs_count} 个 IOC`;
                else if (r.results_count !== undefined) line += ` - ${r.results_count} 条结果`;
                else if (r.techniques_count !== undefined) line += ` - ${r.techniques_count} 项技术`;
                else if (r.matches_count !== undefined) line += ` - ${r.matches_count} 条匹配`;
                else if (r.message) line += ` - ${cleanMessageText(r.message)}`;
                else if (r.error) line += ` - 错误: ${cleanMessageText(r.error)}`;
                return line;
              }).join(', ');
              // 使用递归 JSON 格式化生成详情
              const detailLines: string[] = [];
              for (const r of results) {
                const displayName = cleanToolName(r.name);
                detailLines.push(`▸ 工具: ${displayName}  [${r.ok ? '成功' : '失败'}]`);
                if (r.args) {
                  for (const [key, val] of Object.entries(r.args)) {
                    const valStr = String(val);
                    if (valStr.length > 100) {
                      detailLines.push(`  参数 ${key}: ${valStr.slice(0, 100)}...`);
                    } else {
                      detailLines.push(`  参数 ${key}: ${valStr}`);
                    }
                  }
                }
                if (r.status && r.status !== 'ok') detailLines.push(`  状态: ${r.status}`);
                if (r.message) detailLines.push(`  消息: ${cleanMessageText(r.message)}`);
                if (r.error) detailLines.push(`  错误: ${cleanMessageText(r.error)}`);
                if (r.findings_count !== undefined) detailLines.push(`  发现漏洞: ${r.findings_count} 个`);
                if (r.iocs_count !== undefined) detailLines.push(`  提取 IOC: ${r.iocs_count} 个`);
                if (r.results_count !== undefined) detailLines.push(`  结果数: ${r.results_count} 条`);
                if (r.techniques_count !== undefined) detailLines.push(`  ATT&CK 技术: ${r.techniques_count} 项`);
                if (r.matches_count !== undefined) detailLines.push(`  YARA 匹配: ${r.matches_count} 条`);

                // 递归格式化 result_preview 中的嵌套 JSON
                const resultData = r.result_preview;
                if (resultData) {
                  try {
                    const parsedResult = JSON.parse(resultData);
                    const formatted = formatJsonRecursive(parsedResult, 1);
                    if (formatted) detailLines.push(`  结果详情:\n${formatted}`);
                  } catch {
                    const truncated = resultData.length > 200 ? resultData.slice(0, 200) + '...' : resultData;
                    detailLines.push(`  结果: ${cleanMessageText(truncated)}`);
                  }
                }
              }
              detail = detailLines.join('\n');
            } else {
              content = '执行工具操作';
            }
            break;
          }
          case 'observation': {
            title = '观察结果';
            const observations = data.observations as Array<{ tool: string; result_preview: string; result_full?: string; findings_count?: number; iocs_count?: number; results_count?: number; techniques_count?: number; matches_count?: number }> | undefined;
            if (observations && observations.length > 0) {
              content = observations.map(o => {
                const displayName = cleanToolName(o.tool);
                let line = `${displayName}`;
                if (o.findings_count !== undefined) line += `: 发现 ${o.findings_count} 个漏洞`;
                else if (o.iocs_count !== undefined) line += `: 提取 ${o.iocs_count} 个 IOC`;
                else if (o.results_count !== undefined) line += `: ${o.results_count} 条结果`;
                else if (o.techniques_count !== undefined) line += `: ${o.techniques_count} 项 ATT&CK 技术`;
                else if (o.matches_count !== undefined) line += `: ${o.matches_count} 条 YARA 匹配`;
                else {
                  // 尝试解析 result_preview 中的 JSON，提取 message 等可读字段
                  let preview = o.result_preview;
                  try {
                    const parsed = JSON.parse(preview);
                    preview = parsed.message || parsed.summary || preview;
                  } catch {
                    // 非 JSON，直接使用
                  }
                  line += `: ${cleanMessageText(preview)}`;
                }
                return line;
              }).join('\n');
              // 使用递归 JSON 格式化生成详情
              const detailLines: string[] = [];
              for (const o of observations) {
                const displayName = cleanToolName(o.tool);
                detailLines.push(`▸ 工具: ${displayName}`);
                if (o.findings_count !== undefined) detailLines.push(`  发现漏洞: ${o.findings_count} 个`);
                if (o.iocs_count !== undefined) detailLines.push(`  提取 IOC: ${o.iocs_count} 个`);
                if (o.results_count !== undefined) detailLines.push(`  结果数: ${o.results_count} 条`);
                if (o.techniques_count !== undefined) detailLines.push(`  ATT&CK 技术: ${o.techniques_count} 项`);
                if (o.matches_count !== undefined) detailLines.push(`  YARA 匹配: ${o.matches_count} 条`);
                const resultData = o.result_full || o.result_preview;
                if (resultData) {
                  try {
                    const parsed = JSON.parse(resultData);
                    const formatted = formatJsonRecursive(parsed, 1);
                    if (formatted) detailLines.push(`  结果详情:\n${formatted}`);
                  } catch {
                    const preview = resultData.length > 200 ? resultData.slice(0, 200) + '...' : resultData;
                    detailLines.push(`  结果: ${cleanMessageText(preview)}`);
                  }
                }
              }
              detail = detailLines.join('\n');
            } else {
              content = '获取工具返回结果';
            }
            break;
          }
          case 'done':
            title = '分析完成';
            content = (data.message as string) || '分析完成';
            detail = [
              `耗时: ${data.elapsed_seconds}s`,
              `步骤: ${data.total_steps}`,
              data.confidence ? `置信度: ${data.confidence}(${data.confidence_score}/100)` : '',
            ].filter(Boolean).join('\n');
            break;
          case 'error':
            title = '分析错误';
            content = (data.message as string) || '未知错误';
            if (data.elapsed_seconds) {
              detail = `耗时: ${data.elapsed_seconds}s`;
            }
            break;
        }

        const newStep: DisplayStep = {
          id: `ws-${stepNum}`,
          type: msg.type as StepType,
          title,
          content,
          detail,
          timestamp: new Date().toLocaleTimeString('zh-CN', {
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
          }),
        };

        setSteps((prev) => {
          if (prev.some((s) => s.id === newStep.id)) return prev;
          return [...prev, newStep];
        });
        setExpandedSteps((prev) => new Set([...prev, newStep.id]));

        if (msg.type === 'done' || msg.type === 'error') {
          setIsAnalyzing(false);
          clearActiveTask();
        }
      }
    },
    [taskId]
  );

  // Connect to WebSocket
  const { isReconnecting } = useWebSocket(taskId, { onMessage: handleWsMessage });

  // Save active task to localStorage when taskId exists
  useEffect(() => {
    if (taskId) {
      saveActiveTask(taskId);
    }
  }, [taskId]);

  // No taskId - try to redirect to active task, or show empty state
  if (!taskId) {
    const activeTask = getActiveTask();
    if (activeTask) {
      // Redirect to the active analyzing task
      navigate(`/analysis/${activeTask}`);
      return null;
    }
    return (
      <div style={{ margin: '0 auto', width: '100%', maxWidth: '1200px', padding: '24px 16px' }}>
        <div className="animate-slide-up" style={{ marginBottom: '24px' }}>
          <h1
            style={{
              fontWeight: 600,
              fontSize: '28px',
              lineHeight: '1.3',
              color: 'var(--text-primary)',
            }}
          >
            Agent 分析过程
          </h1>
          <p style={{ marginTop: '4px', fontSize: '14px', color: 'var(--text-secondary)' }}>
            实时查看 AI Agent 的思考链与分析步骤
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
          <FileText size={48} style={{ color: 'var(--text-muted)', marginBottom: '16px' }} />
          <h3
            style={{
              fontWeight: 600,
              fontSize: '18px',
              color: 'var(--text-primary)',
              marginBottom: '8px',
            }}
          >
            尚未选择分析任务
          </h3>
          <p
            style={{
              fontSize: '14px',
              color: 'var(--text-secondary)',
              maxWidth: '400px',
              textAlign: 'center',
              marginBottom: '24px',
            }}
          >
            请先提交代码进行分析，或在历史记录中查看已有任务的分析过程。
          </p>
          <div style={{ display: 'flex', gap: '12px' }}>
            <button
              onClick={() => navigate('/submit')}
              className="gradient-bg"
              style={{
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
              }}
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
              }}
            >
              查看历史记录
            </button>
          </div>
        </div>
      </div>
    );
  }

  // Fetch existing task data and trigger analysis if needed
  useEffect(() => {
    let cancelled = false;

    async function loadAndAnalyze() {
      if (!taskId) return;
      try {
        setIsLoading(true);
        const res = await getTask(Number(taskId));
        const task: TaskResponse = res.data;

        if (cancelled) return;

        // Derive task name from name field, input_path or input_content
        const taskName = task.name
          || (task.input_path
          ? task.input_path.split('/').pop() || task.input_path
          : task.input_content
          ? `代码片段 #${task.id}`
          : `任务 #${task.id}`);

        setTaskInfo({ type: task.type, name: taskName });

        // Convert existing steps to display format
        if (task.analysis_steps && task.analysis_steps.length > 0) {
          const displaySteps: DisplayStep[] = task.analysis_steps.map((step: AnalysisStep) => {
            let stepType: StepType = 'thought';
            let rawContent = '';
            if (step.thought) {
              stepType = 'thought';
              rawContent = step.thought;
            } else if (step.action) {
              stepType = 'action';
              rawContent = step.action;
            } else if (step.observation) {
              stepType = 'observation';
              rawContent = step.observation;
            }
            return parseStepFromRaw(stepType, rawContent, `step-${step.id}`, step.created_at);
          });
          setSteps(displaySteps);
          setExpandedSteps(new Set(displaySteps.map((s) => s.id)));
          setTotalSteps(Math.max(displaySteps.length, 4));

          // Check if analysis is complete
          if (task.status === 'done' || task.status === 'failed') {
            setIsAnalyzing(false);
          }
        }

        // If task is already done/failed, stop analyzing and clear active task
        if (task.status === 'done' || task.status === 'failed') {
          setIsAnalyzing(false);
          clearActiveTask();
        }
      } catch (error) {
        setTaskNotFound(true);
        setIsAnalyzing(false);
      } finally {
        setIsLoading(false);
      }
    }

    loadAndAnalyze();

    return () => {
      cancelled = true;
    };
  }, [taskId]);

  // ── 轮询补偿：当任务处于 analyzing 状态时，定期从 HTTP API 获取步骤 ──
  // 解决 WebSocket 连接延迟导致消息丢失的问题
  useEffect(() => {
    if (!taskId || !isAnalyzing) return;

    const POLL_INTERVAL = 2000; // 每 2 秒轮询一次
    let pollTimer: ReturnType<typeof setInterval>;

    async function pollSteps() {
      try {
        // 先获取任务状态
        const taskRes = await getTask(Number(taskId));
        const task = taskRes.data;

        // 获取最新步骤
        const stepsRes = await getTaskSteps(Number(taskId));
        const apiSteps: AnalysisStep[] = stepsRes.data;

        if (apiSteps && apiSteps.length > 0) {
          // 将 API 步骤转换为 DisplayStep
          const newDisplaySteps: DisplayStep[] = apiSteps.map((step: AnalysisStep) => {
            let stepType: StepType = 'thought';
            let rawContent = '';
            if (step.thought) {
              stepType = 'thought';
              rawContent = step.thought;
            } else if (step.action) {
              stepType = 'action';
              rawContent = step.action;
            } else if (step.observation) {
              stepType = 'observation';
              rawContent = step.observation;
            }
            return parseStepFromRaw(stepType, rawContent, `step-${step.id}`, step.created_at);
          });

          // 找出新增的步骤，逐个延迟添加以实现流式动画效果
          setSteps((prev) => {
            const existingIds = new Set(prev.map(s => s.id));
            const trulyNew = newDisplaySteps.filter(ds => !existingIds.has(ds.id));
            if (trulyNew.length === 0) return prev;

            // 逐个延迟添加新步骤，产生流式出现效果
            trulyNew.forEach((ds, i) => {
              setTimeout(() => {
                setSteps(p => {
                  if (p.some(s => s.id === ds.id)) return p;
                  return [...p, ds];
                });
                setExpandedSteps(p => new Set([...p, ds.id]));
              }, i * 300); // 每个新步骤间隔 300ms 出现
            });

            return prev;
          });
        }

        // 如果任务完成，停止轮询
        if (task.status === 'done' || task.status === 'failed') {
          setIsAnalyzing(false);
          clearActiveTask();
        }
      } catch {
        // 轮询失败不影响主流程
      }
    }

    pollTimer = setInterval(pollSteps, POLL_INTERVAL);

    return () => {
      clearInterval(pollTimer);
    };
  }, [taskId, isAnalyzing]);

  const toggleExpand = (stepId: string) => {
    setExpandedSteps((prev) => {
      const newSet = new Set(prev);
      if (newSet.has(stepId)) newSet.delete(stepId);
      else newSet.add(stepId);
      return newSet;
    });
  };

  const progressPct = steps.length > 0 ? Math.min(Math.round((steps.length / Math.max(totalSteps, steps.length)) * 100), 100) : 0;

  // Task not found state
  if (taskNotFound) {
    return (
      <div style={{ margin: '0 auto', width: '100%', maxWidth: '1200px', padding: '24px 16px' }}>
        <div className="animate-slide-up" style={{ marginBottom: '24px' }}>
          <h1
            style={{
              fontWeight: 600,
              fontSize: '28px',
              lineHeight: '1.3',
              color: 'var(--text-primary)',
            }}
          >
            Agent 分析过程
          </h1>
          <p style={{ marginTop: '4px', fontSize: '14px', color: 'var(--text-secondary)' }}>
            实时查看 AI Agent 的思考链与分析步骤
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
          <FileText size={48} style={{ color: 'var(--text-muted)', marginBottom: '16px' }} />
          <h3
            style={{
              fontWeight: 600,
              fontSize: '18px',
              color: 'var(--text-primary)',
              marginBottom: '8px',
            }}
          >
            尚未选择分析任务
          </h3>
          <p
            style={{
              fontSize: '14px',
              color: 'var(--text-secondary)',
              maxWidth: '400px',
              textAlign: 'center',
              marginBottom: '24px',
            }}
          >
            请先提交代码进行分析，或在历史记录中查看已有任务的分析过程。
          </p>
          <div style={{ display: 'flex', gap: '12px' }}>
            <button
              onClick={() => navigate('/submit')}
              className="gradient-bg"
              style={{
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
              }}
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
              }}
            >
              查看历史记录
            </button>
          </div>
        </div>
      </div>
    );
  }

  // Loading state
  if (isLoading) {
    return (
      <div style={{ margin: '0 auto', width: '100%', maxWidth: '1200px', padding: '24px 16px' }}>
        <div className="animate-slide-up" style={{ marginBottom: '24px' }}>
          <h1
            style={{
              fontWeight: 600,
              fontSize: '28px',
              lineHeight: '1.3',
              color: 'var(--text-primary)',
            }}
          >
            Agent 分析过程
          </h1>
          <p style={{ marginTop: '4px', fontSize: '14px', color: 'var(--text-secondary)' }}>
            实时查看 AI Agent 的思考链与分析步骤
          </p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '80px 0' }}>
          <Spin size="large" tip="正在加载任务数据...">
            <div style={{ padding: 50 }} />
          </Spin>
        </div>
      </div>
    );
  }

  return (
    <div style={{ margin: '0 auto', width: '100%', maxWidth: '1200px', padding: '24px 16px' }}>
      {/* Page Title + Progress */}
      <div className="animate-slide-up" style={{ marginBottom: '16px' }}>
        <div
          style={{
            display: 'flex',
            alignItems: 'flex-start',
            justifyContent: 'space-between',
            gap: '12px',
            flexDirection: 'row',
          }}
        >
          <div>
            <h1
              style={{
                fontWeight: 600,
                fontSize: '28px',
                lineHeight: '1.3',
                color: 'var(--text-primary)',
              }}
            >
              Agent 分析过程
            </h1>
            <p style={{ marginTop: '4px', fontSize: '14px', color: 'var(--text-secondary)' }}>
              实时查看 AI Agent 的思考链与分析步骤
            </p>
          </div>
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              borderRadius: '12px',
              padding: '8px 16px',
              background: isAnalyzing ? 'rgba(91,163,255,0.06)' : 'rgba(16,185,129,0.06)',
              color: isAnalyzing ? '#5BA3FF' : '#10B981',
            }}
          >
            {isAnalyzing ? (
              <>
                <Loader2 size={16} className="animate-spin" />
                <span style={{ fontSize: '14px', fontWeight: 500 }}>
                  {isReconnecting ? '重新连接中...' : '分析中...'}
                </span>
              </>
            ) : (
              <>
                <CheckCircle2 size={16} />
                <span style={{ fontSize: '14px', fontWeight: 500 }}>分析完成</span>
              </>
            )}
          </div>
        </div>

        {/* Progress Bar */}
        <div style={{ marginTop: '16px' }}>
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              fontSize: '12px',
              marginBottom: '8px',
            }}
          >
            <span style={{ color: 'var(--text-secondary)' }}>
              步骤 {steps.length}
            </span>
            <span
              style={{
                fontWeight: 500,
                color: isAnalyzing ? 'var(--accent-start)' : 'var(--semantic-success)',
              }}
            >
              {progressPct}%
            </span>
          </div>
          <div
            style={{
              height: '8px',
              overflow: 'hidden',
              borderRadius: '9999px',
              background: 'rgba(148,163,184,0.08)',
            }}
          >
            <div
              style={{
                height: '100%',
                borderRadius: '9999px',
                transition: 'all 0.5s',
                width: `${progressPct}%`,
                background: isAnalyzing ? 'var(--accent-gradient)' : 'var(--semantic-success)',
              }}
            />
          </div>
        </div>

        {/* Task Info Bar */}
        <div
          style={{
            marginTop: '16px',
            display: 'flex',
            flexWrap: 'wrap',
            alignItems: 'center',
            gap: '16px',
            borderRadius: '12px',
            border: '1px solid var(--border-light)',
            padding: '12px',
          }}
        >
          <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            任务 ID: {taskId}
          </span>
          <span
            style={{
              display: 'inline-block',
              width: '1px',
              height: '12px',
              background: 'var(--border-light)',
            }}
          />
          <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            类型: {typeLabels[taskInfo?.type || ''] || taskInfo?.type}
          </span>
          <span
            style={{
              display: 'inline-block',
              width: '1px',
              height: '12px',
              background: 'var(--border-light)',
            }}
          />
          <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            文件: {taskInfo?.name || taskId}
          </span>
        </div>
      </div>

      {/* Thought Chain Cards */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
        {steps.map((step, index) => {
          const config = stepConfig[step.type];
          const Icon = config.icon;
          const isExpanded = expandedSteps.has(step.id);
          const isLastStep = index === steps.length - 1;
          const isCurrentlyAnalyzing = isAnalyzing && isLastStep;

          return (
            <div key={step.id} className="timeline-connector">
              <div
                className="stagger-card"
                style={{
                  overflow: 'hidden',
                  borderRadius: '16px',
                  border: '1px solid',
                  borderColor: isExpanded ? config.borderColor : 'var(--border-light)',
                  boxShadow: isExpanded ? config.bgColor : 'var(--shadow-sm)',
                  animationDelay: `${index * 80}ms`,
                  transition: 'box-shadow 0.15s',
                }}
              >
                {/* Card Header */}
                <button
                  onClick={() => toggleExpand(step.id)}
                  style={{
                    display: 'flex',
                    width: '100%',
                    alignItems: 'center',
                    gap: '16px',
                    padding: '12px 20px',
                    textAlign: 'left',
                    background: 'none',
                    border: 'none',
                    cursor: 'pointer',
                  }}
                >
                  {/* Step Number */}
                  <div
                    className={isCurrentlyAnalyzing ? 'step-number-active step-pulse-active' : ''}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      borderRadius: '12px',
                      fontSize: '12px',
                      fontWeight: 700,
                      width: '32px',
                      height: '32px',
                      background: isCurrentlyAnalyzing ? undefined : config.bgColor,
                      color: isCurrentlyAnalyzing ? undefined : config.color,
                      flexShrink: 0,
                    }}
                  >
                    {index + 1}
                  </div>

                  {/* Icon + Label + Title */}
                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '8px',
                      flex: 1,
                      minWidth: 0,
                    }}
                  >
                    <Icon size={16} style={{ color: config.color }} />
                    <span
                      style={{
                        fontSize: '12px',
                        fontWeight: 600,
                        textTransform: 'uppercase',
                        letterSpacing: '0.05em',
                        color: config.color,
                      }}
                    >
                      {config.label}
                    </span>
                    <span
                      style={{
                        fontSize: '14px',
                        fontWeight: 500,
                        color: 'var(--text-primary)',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap',
                      }}
                    >
                      {step.title}
                    </span>
                  </div>

                  {/* Right Side */}
                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '12px',
                      flexShrink: 0,
                    }}
                  >
                    <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                      {step.timestamp}
                    </span>
                    {isCurrentlyAnalyzing && (
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <span
                          className="animate-pulse-soft"
                          style={{
                            display: 'inline-block',
                            width: '8px',
                            height: '8px',
                            borderRadius: '50%',
                            background: config.color,
                          }}
                        />
                        <span
                          className="animate-pulse-soft"
                          style={{ fontSize: '12px', fontWeight: 500, color: config.color }}
                        >
                          执行中
                        </span>
                      </div>
                    )}
                    {step.detail &&
                      (isExpanded ? (
                        <ChevronUp size={16} style={{ color: 'var(--text-muted)' }} />
                      ) : (
                        <ChevronDown size={16} style={{ color: 'var(--text-muted)' }} />
                      ))}
                  </div>
                </button>

                {/* Card Body */}
                {isExpanded && (
                  <div
                    style={{
                      borderTop: '1px solid var(--border-light)',
                      padding: '12px 20px 16px',
                    }}
                  >
                    <div
                      style={{
                        fontSize: '14px',
                        lineHeight: 1.625,
                        color: 'var(--text-primary)',
                      }}
                    >
                      {step.content}
                    </div>
                    {step.detail && (
                      <div
                        style={{
                          marginTop: '12px',
                          overflow: 'hidden',
                          borderRadius: '12px',
                          padding: '16px',
                          background: 'rgba(148,163,184,0.04)',
                          border: '1px solid var(--border-light)',
                        }}
                      >
                        <div
                          style={{
                            marginBottom: '8px',
                            fontSize: '12px',
                            fontWeight: 600,
                            textTransform: 'uppercase',
                            letterSpacing: '0.05em',
                            color: 'var(--text-secondary)',
                          }}
                        >
                          详细信息
                        </div>
                        <pre
                          className="custom-scrollbar"
                          style={{
                            overflowX: 'auto',
                            fontSize: '12px',
                            lineHeight: 1.625,
                            fontFamily: "'JetBrains Mono', 'Fira Code', Consolas, monospace",
                            color: 'var(--text-secondary)',
                            margin: 0,
                          }}
                        >
                          {step.detail}
                        </pre>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          );
        })}

        {/* Pending Steps Indicator */}
        {isAnalyzing && (
          <div
            className="animate-pulse-soft"
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '16px',
              borderRadius: '16px',
              border: '1px dashed var(--border-normal)',
              padding: '16px 20px',
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
                background: 'rgba(148,163,184,0.06)',
                flexShrink: 0,
              }}
            >
              <Loader2 size={16} className="animate-spin" style={{ color: 'var(--text-muted)' }} />
            </div>
            <span style={{ fontSize: '14px', color: 'var(--text-muted)' }}>
              Agent 正在思考下一步操作...
            </span>
          </div>
        )}
      </div>

      {/* View Report Button - shown after analysis completes */}
      {!isAnalyzing && (
        <div
          className="animate-slide-up"
          style={{ marginTop: '32px', display: 'flex', justifyContent: 'center' }}
        >
          <button
            onClick={() => navigate(`/report/${taskId}`)}
            className="gradient-bg"
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              borderRadius: '12px',
              padding: '12px 32px',
              fontSize: '14px',
              fontWeight: 500,
              color: 'white',
              border: 'none',
              cursor: 'pointer',
              boxShadow: 'var(--shadow-brand)',
              transition: 'opacity 0.15s',
            }}
          >
            <FileText size={16} />
            查看分析报告
            <ArrowRight size={14} />
          </button>
        </div>
      )}
    </div>
  );
};

export default Analysis;
