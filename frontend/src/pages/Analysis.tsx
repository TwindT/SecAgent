import { useState, useEffect, useRef, useCallback } from 'react';
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
import { getTask, triggerAnalysis } from '@/services/api';
import type { TaskResponse, AnalysisStep } from '@/services/api';
import { useWebSocket } from '@/hooks/useWebSocket';
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
  code_scan: '代码漏洞检测',
};

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
  const triggeredRef = useRef(false);

  // WebSocket message handler
  const handleWsMessage = useCallback(
    (msg: WSMessage) => {
      if (!taskId) return;

      const data = msg.data;

      if (msg.type === 'thought' || msg.type === 'action' || msg.type === 'observation' || msg.type === 'done' || msg.type === 'error') {
        const stepNum = data.stepNum as number;
        const title = (data.title as string) || '';
        const content = (data.content as string) || '';
        const detail = data.detail as string | undefined;

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
        }
      }
    },
    [taskId]
  );

  // Connect to WebSocket
  useWebSocket(taskId, { onMessage: handleWsMessage });

  // No taskId - show empty state directly
  if (!taskId) {
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

        // Derive task name from input_path or input_content
        const taskName = task.input_path
          ? task.input_path.split('/').pop() || task.input_path
          : task.input_content
          ? `代码片段 #${task.id}`
          : `任务 #${task.id}`;

        setTaskInfo({ type: task.type, name: taskName });

        // Convert existing steps to display format
        if (task.analysis_steps && task.analysis_steps.length > 0) {
          const displaySteps: DisplayStep[] = task.analysis_steps.map((step: AnalysisStep) => {
            // Determine step type from available fields
            let stepType: StepType = 'thought';
            let stepTitle = '';
            let stepContent = '';
            if (step.thought) {
              stepType = 'thought';
              stepTitle = '思考';
              stepContent = step.thought;
            } else if (step.action) {
              stepType = 'action';
              stepTitle = '执行操作';
              stepContent = step.action;
            } else if (step.observation) {
              stepType = 'observation';
              stepTitle = '观察结果';
              stepContent = step.observation;
            }

            return {
              id: `step-${step.id}`,
              type: stepType,
              title: stepTitle,
              content: stepContent,
              timestamp: new Date(step.created_at).toLocaleTimeString('zh-CN', {
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
              }),
            };
          });
          setSteps(displaySteps);
          setExpandedSteps(new Set(displaySteps.map((s) => s.id)));
          setTotalSteps(Math.max(displaySteps.length, 4));

          // Check if analysis is complete
          if (task.status === 'done' || task.status === 'failed') {
            setIsAnalyzing(false);
          }
        }

        // If task is still pending and we haven't triggered analysis yet, trigger it
        if ((task.status === 'pending' || task.status === 'analyzing') && !triggeredRef.current) {
          triggeredRef.current = true;
          triggerAnalysis(Number(taskId))
            .then(() => {
              // Refresh steps after analysis completes
              getTask(Number(taskId)).then((res2) => {
                if (cancelled) return;
                const updatedTask = res2.data;
                if (updatedTask.analysis_steps && updatedTask.analysis_steps.length > 0) {
                  const displaySteps: DisplayStep[] = updatedTask.analysis_steps.map((step: AnalysisStep) => {
                    let stepType: StepType = 'thought';
                    let stepTitle = '';
                    let stepContent = '';
                    if (step.thought) {
                      stepType = 'thought';
                      stepTitle = '思考';
                      stepContent = step.thought;
                    } else if (step.action) {
                      stepType = 'action';
                      stepTitle = '执行操作';
                      stepContent = step.action;
                    } else if (step.observation) {
                      stepType = 'observation';
                      stepTitle = '观察结果';
                      stepContent = step.observation;
                    }

                    return {
                      id: `step-${step.id}`,
                      type: stepType,
                      title: stepTitle,
                      content: stepContent,
                      timestamp: new Date(step.created_at).toLocaleTimeString('zh-CN', {
                        hour: '2-digit',
                        minute: '2-digit',
                        second: '2-digit',
                      }),
                    };
                  });
                  setSteps(displaySteps);
                  setExpandedSteps(new Set(displaySteps.map((s) => s.id)));
                  setTotalSteps(displaySteps.length);
                  setIsAnalyzing(false);
                }
              });
            })
            .catch((err) => {
              console.error('Failed to trigger analysis:', err);
            });
        }

        // If task is already done/failed, stop analyzing
        if (task.status === 'done' || task.status === 'failed') {
          setIsAnalyzing(false);
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

  const toggleExpand = (stepId: string) => {
    setExpandedSteps((prev) => {
      const newSet = new Set(prev);
      if (newSet.has(stepId)) newSet.delete(stepId);
      else newSet.add(stepId);
      return newSet;
    });
  };

  const progressPct = totalSteps > 0 ? Math.round((steps.length / totalSteps) * 100) : 0;

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
                <span style={{ fontSize: '14px', fontWeight: 500 }}>分析中...</span>
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
              步骤 {steps.length} / {totalSteps}
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
            类型: {typeLabels[taskInfo?.type || 'code_scan']}
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
