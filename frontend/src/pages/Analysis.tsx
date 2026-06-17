import { useState, useEffect, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { Spin } from 'antd';
import {
  Brain,
  Wrench,
  Eye,
  CheckCircle2,
  XCircle,
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

// ─── Fallback content for steps without summary ─────
/**
 * 当后端未提供 summary 字段时（如旧数据或 summarizer 不可用），
 * 提供简单的兜底文本。
 */
function getFallbackContent(stepType: StepType, data: Record<string, unknown>): string {
  switch (stepType) {
    case 'thought':
      return (data.content as string) || 'Agent 正在思考下一步分析策略';
    case 'action':
      return '执行工具操作';
    case 'observation':
      return '获取工具返回结果';
    case 'done':
      return (data.message as string) || '分析完成';
    case 'error':
      return (data.message as string) || '未知错误';
    default:
      return '分析步骤';
  }
}

// ─── Shared step parser (simplified) ────────────────
/**
 * 将后端存储的原始 step 数据（JSON 字符串）解析为 DisplayStep。
 * 优先使用 data.summary 字段（由后端 qwen-plus 总结生成），
 * 如果没有则使用兜底文本。
 */
function parseStepFromRaw(
  stepType: StepType,
  rawContent: string,
  stepId: string,
  createdAt: string,
): DisplayStep {
  const titleMap: Record<StepType, string> = {
    thought: '思考',
    action: '执行操作',
    observation: '观察结果',
    done: '分析完成',
    error: '分析错误',
  };

  let content: string;
  try {
    const parsed = JSON.parse(rawContent);
    // 优先使用 summary 字段（后端 qwen-plus 总结的纯文本）
    if (typeof parsed.summary === 'string' && parsed.summary.trim()) {
      content = parsed.summary.trim();
    } else {
      content = getFallbackContent(stepType, parsed);
    }
  } catch {
    // 非 JSON 字符串，直接使用
    content = rawContent || getFallbackContent(stepType, {});
  }

  return {
    id: stepId,
    type: stepType,
    title: titleMap[stepType] || stepType,
    content,
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
  const [isAnalyzing, setIsAnalyzing] = useState(true);
  const [taskInfo, setTaskInfo] = useState<{ type: string; name: string } | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [taskNotFound, setTaskNotFound] = useState(false);
  const [totalSteps, setTotalSteps] = useState(8);

  // WebSocket message handler
  const handleWsMessage = useCallback(
    (msg: WSMessage) => {
      if (!taskId) return;

      const normalizedMsg = normalizeWSMessage(msg);
      const data = normalizedMsg.data;

      if (msg.type === 'thought' || msg.type === 'action' || msg.type === 'observation' || msg.type === 'done' || msg.type === 'error') {
        const stepNum = (data.step_num ?? data.stepNum) as number;

        const titleMap: Record<string, string> = {
          thought: '思考',
          action: '执行操作',
          observation: '观察结果',
          done: '分析完成',
          error: '分析错误',
        };

        // 优先使用后端总结的 summary 字段
        let content: string;
        if (typeof data.summary === 'string' && data.summary.trim()) {
          content = data.summary.trim();
        } else {
          content = getFallbackContent(msg.type as StepType, data);
        }

        const newStep: DisplayStep = {
          id: `ws-${stepNum}`,
          type: msg.type as StepType,
          title: titleMap[msg.type] || msg.type,
          content,
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

  // Fetch existing task data and trigger analysis if needed
  useEffect(() => {
    if (!taskId) return;
    let cancelled = false;

    async function loadAndAnalyze() {
      try {
        setIsLoading(true);
        const res = await getTask(Number(taskId));
        const task: TaskResponse = res.data;

        if (cancelled) return;

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
          setTotalSteps(Math.max(displaySteps.length, 4));

          if (task.status === 'done' || task.status === 'failed') {
            setIsAnalyzing(false);
          }
        }

        if (task.status === 'done' || task.status === 'failed') {
          setIsAnalyzing(false);
          clearActiveTask();
        }
      } catch {
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
  useEffect(() => {
    if (!taskId || !isAnalyzing) return;

    const POLL_INTERVAL = 2000;
    const pollTimer = setInterval(async () => {
      try {
        const taskRes = await getTask(Number(taskId));
        const task = taskRes.data;

        const stepsRes = await getTaskSteps(Number(taskId));
        const apiSteps: AnalysisStep[] = stepsRes.data;

        if (apiSteps && apiSteps.length > 0) {
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

            trulyNew.forEach((ds, i) => {
              setTimeout(() => {
                setSteps(p => {
                  if (p.some(s => s.id === ds.id)) return p;
                  return [...p, ds];
                });
              }, i * 300);
            });

            return prev;
          });
        }

        if (task.status === 'done' || task.status === 'failed') {
          setIsAnalyzing(false);
          clearActiveTask();
        }
      } catch {
        // 轮询失败不影响主流程
      }
    }, POLL_INTERVAL);

    return () => {
      clearInterval(pollTimer);
    };
  }, [taskId, isAnalyzing]);

  // No taskId - try to redirect to active task, or show empty state
  if (!taskId) {
    const activeTask = getActiveTask();
    if (activeTask) {
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
                  borderColor: config.borderColor,
                  boxShadow: config.bgColor,
                  animationDelay: `${index * 80}ms`,
                  transition: 'box-shadow 0.15s',
                }}
              >
                {/* Card Header */}
                <div
                  style={{
                    display: 'flex',
                    width: '100%',
                    alignItems: 'center',
                    gap: '16px',
                    padding: '12px 20px',
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
                  </div>
                </div>

                {/* Card Body - 直接展示纯文本摘要 */}
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
                      whiteSpace: 'pre-wrap',
                      wordBreak: 'break-word',
                    }}
                  >
                    {step.content}
                  </div>
                </div>
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
