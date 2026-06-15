import { useState, useEffect, useRef, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { message, Modal, Spin, DatePicker } from 'antd';
import type { Dayjs } from 'dayjs';
import {
  Search,
  Trash2,
  Code2,
  Bug,
  ChevronLeft,
  ChevronRight,
  AlertTriangle,
  Eye,
  Calendar,
  X,
  RefreshCw,
} from 'lucide-react';
import { getTaskList, deleteTask } from '../services/api';
import type { TaskResponse } from '../services/api';

const { RangePicker } = DatePicker;

// ─── Status Helpers ─────────────────────────────────
function getStatusBadge(status: string) {
  const config: Record<string, { label: string; bg: string; color: string; pulse?: boolean }> = {
    done: { label: '完成', bg: 'rgba(16,185,129,0.1)', color: '#10B981' },
    analyzing: { label: '分析中', bg: 'rgba(91,163,255,0.1)', color: '#5BA3FF', pulse: true },
    failed: { label: '失败', bg: 'rgba(239,68,68,0.1)', color: '#EF4444' },
    pending: { label: '等待中', bg: 'rgba(148,163,184,0.1)', color: '#94A3B8' },
  };
  const c = config[status];
  if (!c) return null;
  return (
    <span
      className={c.pulse ? 'animate-pulse-soft' : ''}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '6px',
        borderRadius: '8px',
        padding: '4px 10px',
        fontSize: '12px',
        fontWeight: 500,
        background: c.bg,
        color: c.color,
      }}
    >
      {c.label}
    </span>
  );
}

function getSeverityBadge(severity: string | null | undefined) {
  if (!severity) return <span style={{ color: 'var(--text-muted)' }}>—</span>;
  const config: Record<string, { label: string; color: string; bg: string }> = {
    high: { label: '高危', color: '#EF4444', bg: 'rgba(239,68,68,0.08)' },
    medium: { label: '中危', color: '#F59E0B', bg: 'rgba(245,158,11,0.08)' },
    low: { label: '低危', color: '#10B981', bg: 'rgba(16,185,129,0.08)' },
    info: { label: '信息', color: '#94A3B8', bg: 'rgba(148,163,184,0.08)' },
  };
  const c = config[severity];
  if (!c) return null;
  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '6px',
        borderRadius: '8px',
        padding: '4px 10px',
        fontSize: '12px',
        fontWeight: 500,
        background: c.bg,
        color: c.color,
      }}
    >
      <span
        style={{
          display: 'inline-block',
          borderRadius: '50%',
          width: '6px',
          height: '6px',
          background: c.color,
        }}
      />
      {c.label}
    </span>
  );
}

// ─── Derive display name from task ──────────────────
function getTaskDisplayName(task: TaskResponse): string {
  if (task.input_path) {
    return task.input_path.split('/').pop() || task.input_path;
  }
  if (task.input_content) {
    return `代码片段 #${task.id}`;
  }
  return `任务 #${task.id}`;
}

function getTaskDuration(task: TaskResponse): string {
  if (task.updated_at && task.created_at) {
    const start = new Date(task.created_at).getTime();
    const end = new Date(task.updated_at).getTime();
    const diffSec = Math.round((end - start) / 1000);
    if (diffSec < 60) return `${diffSec}s`;
    const min = Math.floor(diffSec / 60);
    const sec = diffSec % 60;
    return `${min}m ${sec}s`;
  }
  return '—';
}

// ─── Pagination helper: generate visible page numbers ────
function getPageNumbers(current: number, total: number): (number | '...')[] {
  if (total <= 7) return Array.from({ length: total }, (_, i) => i + 1);
  const pages: (number | '...')[] = [1];
  if (current > 3) pages.push('...');
  const start = Math.max(2, current - 1);
  const end = Math.min(total - 1, current + 1);
  for (let i = start; i <= end; i++) pages.push(i);
  if (current < total - 2) pages.push('...');
  pages.push(total);
  return pages;
}

// ─── Component ──────────────────────────────────────
const History = () => {
  const navigate = useNavigate();
  const [searchQuery, setSearchQuery] = useState('');
  const [filterType, setFilterType] = useState<'all' | 'vulnerability_detection' | 'malware_analysis'>('all');
  const [filterStatus, setFilterStatus] = useState<'all' | 'done' | 'analyzing' | 'failed' | 'pending'>('all');
  const [dateRange, setDateRange] = useState<[Dayjs | null, Dayjs | null] | null>(null);
  const [currentPage, setCurrentPage] = useState(1);
  const [tasks, setTasks] = useState<TaskResponse[]>([]);
  const [totalTasks, setTotalTasks] = useState(0);
  const [totalPages, setTotalPages] = useState(1);
  const [isLoading, setIsLoading] = useState(true);
  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set());
  const [isBatchDeleting, setIsBatchDeleting] = useState(false);
  const pageSize = 8;
  const searchTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [debouncedSearch, setDebouncedSearch] = useState('');

  // Debounce search query
  useEffect(() => {
    if (searchTimerRef.current) {
      clearTimeout(searchTimerRef.current);
    }
    searchTimerRef.current = setTimeout(() => {
      setDebouncedSearch(searchQuery);
    }, 300);
    return () => {
      if (searchTimerRef.current) clearTimeout(searchTimerRef.current);
    };
  }, [searchQuery]);

  // Fetch tasks from API
  const loadTasks = useCallback(async () => {
    setIsLoading(true);
    setSelectedIds(new Set());
    try {
      const params: Record<string, unknown> = {
        page: currentPage,
        page_size: pageSize,
      };
      if (filterType !== 'all') params.type = filterType;
      if (filterStatus !== 'all') params.status = filterStatus;
      if (debouncedSearch) params.search = debouncedSearch;
      if (dateRange && dateRange[0]) params.date_from = dateRange[0].format('YYYY-MM-DD');
      if (dateRange && dateRange[1]) params.date_to = dateRange[1].format('YYYY-MM-DD');

      const res = await getTaskList(params as any);
      const data = res.data;
      setTasks(data.tasks);
      setTotalTasks(data.total);
      setTotalPages(Math.ceil(data.total / pageSize));
    } catch (err) {
      console.error('Failed to load tasks:', err);
    } finally {
      setIsLoading(false);
    }
  }, [currentPage, filterType, filterStatus, debouncedSearch, dateRange, pageSize]);

  useEffect(() => {
    loadTasks();
  }, [loadTasks]);

  const toggleSelect = (taskId: number) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(taskId)) next.delete(taskId);
      else next.add(taskId);
      return next;
    });
  };

  const toggleSelectAll = () => {
    if (selectedIds.size === tasks.length) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(tasks.map((t) => t.id)));
    }
  };

  const handleBatchDelete = async () => {
    setIsBatchDeleting(true);
    let successCount = 0;
    for (const id of selectedIds) {
      try {
        await deleteTask(id);
        successCount++;
      } catch (err) {
        console.error('Failed to delete task:', id, err);
      }
    }
    setSelectedIds(new Set());
    setIsBatchDeleting(false);
    message.success(`批量删除完成：成功删除 ${successCount}/${selectedIds.size} 个任务`);
    loadTasks();
  };

  const handleDelete = async (taskId: number) => {
    try {
      await deleteTask(taskId);
      message.success(`任务 ${taskId} 已成功删除`);
      // Refresh list - if current page is now empty, go to previous page
      const res = await getTaskList({
        page: currentPage,
        page_size: pageSize,
        ...(filterType !== 'all' && { type: filterType }),
        ...(filterStatus !== 'all' && { status: filterStatus }),
        ...(debouncedSearch && { search: debouncedSearch }),
      });
      const data = res.data;
      setTasks(data.tasks);
      setTotalTasks(data.total);
      setTotalPages(Math.ceil(data.total / pageSize));
      if (data.tasks.length === 0 && currentPage > 1) {
        setCurrentPage((p) => p - 1);
      }
    } catch (err) {
      console.error('Failed to delete task:', err);
      message.error('删除失败，请稍后重试');
    }
  };

  const showDeleteConfirm = (taskId: number) => {
    Modal.confirm({
      title: '确认删除',
      content: `确定要删除任务 ${taskId} 吗？删除后相关分析结果将无法恢复。`,
      okText: '确认删除',
      okType: 'danger',
      cancelText: '取消',
      onOk: () => handleDelete(taskId),
    });
  };

  const showBatchDeleteConfirm = () => {
    Modal.confirm({
      title: '批量删除确认',
      content: `确定要删除选中的 ${selectedIds.size} 个任务吗？删除后相关分析结果将无法恢复。`,
      okText: `确认删除 ${selectedIds.size} 项`,
      okType: 'danger',
      cancelText: '取消',
      onOk: handleBatchDelete,
    });
  };

  const clearFilters = () => {
    setSearchQuery('');
    setFilterType('all');
    setFilterStatus('all');
    setDateRange(null);
    setCurrentPage(1);
  };

  const hasActiveFilters = filterType !== 'all' || filterStatus !== 'all' || debouncedSearch || dateRange;

  return (
    <div style={{ margin: '0 auto', width: '100%', maxWidth: '1200px', padding: '24px 16px' }}>
      {/* Page Title */}
      <div className="animate-slide-up" style={{ marginBottom: '16px' }}>
        <h1
          style={{
            fontWeight: 600,
            fontSize: '28px',
            lineHeight: '1.3',
            color: 'var(--text-primary)',
          }}
        >
          历史任务
        </h1>
        <p style={{ marginTop: '4px', fontSize: '14px', color: 'var(--text-secondary)' }}>
          管理和查看所有安全分析任务
        </p>
      </div>

      {/* Filters & Search Bar */}
      <div
        className="animate-slide-up"
        style={{
          marginBottom: '16px',
          display: 'flex',
          flexWrap: 'wrap',
          alignItems: 'center',
          gap: '12px',
          animationDelay: '60ms',
          animationFillMode: 'both',
        }}
      >
        {/* Search */}
        <div style={{ position: 'relative', width: '100%', flex: '1 1 240px', minWidth: '240px' }}>
          <Search
            size={16}
            style={{
              position: 'absolute',
              left: '14px',
              top: '50%',
              transform: 'translateY(-50%)',
              color: 'var(--text-muted)',
            }}
          />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => {
              setSearchQuery(e.target.value);
              setCurrentPage(1);
            }}
            placeholder="搜索任务名称或 ID..."
            style={{
              width: '100%',
              borderRadius: '12px',
              border: '1px solid var(--border-normal)',
              background: 'var(--bg-card)',
              padding: '10px 16px 10px 40px',
              fontSize: '14px',
              color: 'var(--text-primary)',
              outline: 'none',
              transition: 'border-color 0.15s',
            }}
            onFocus={(e) => {
              e.currentTarget.style.borderColor = 'var(--border-focus)';
            }}
            onBlur={(e) => {
              e.currentTarget.style.borderColor = 'var(--border-normal)';
            }}
          />
        </div>

        {/* Type Filter */}
        <div
          style={{
            display: 'flex',
            borderRadius: '12px',
            padding: '4px',
            gap: '2px',
            background: 'rgba(148,163,184,0.06)',
          }}
        >
          {[
            { value: 'all' as const, label: '全部' },
            { value: 'vulnerability_detection' as const, label: '代码扫描' },
            { value: 'malware_analysis' as const, label: '恶意分析' },
          ].map((opt) => (
            <button
              key={opt.value}
              onClick={() => {
                setFilterType(opt.value);
                setCurrentPage(1);
              }}
              style={{
                borderRadius: '8px',
                padding: '8px 14px',
                fontSize: '12px',
                fontWeight: 500,
                border: 'none',
                cursor: 'pointer',
                transition: 'all 0.15s',
                background: filterType === opt.value ? 'var(--bg-card)' : 'transparent',
                color: filterType === opt.value ? 'var(--accent-start)' : 'var(--text-secondary)',
                boxShadow: filterType === opt.value ? 'var(--shadow-sm)' : 'none',
              }}
            >
              {opt.label}
            </button>
          ))}
        </div>

        {/* Status Filter */}
        <div
          style={{
            display: 'flex',
            borderRadius: '12px',
            padding: '4px',
            gap: '2px',
            background: 'rgba(148,163,184,0.06)',
          }}
        >
          {[
            { value: 'all' as const, label: '全部状态' },
            { value: 'done' as const, label: '完成' },
            { value: 'analyzing' as const, label: '分析中' },
            { value: 'failed' as const, label: '失败' },
            { value: 'pending' as const, label: '等待中' },
          ].map((opt) => (
            <button
              key={opt.value}
              onClick={() => {
                setFilterStatus(opt.value);
                setCurrentPage(1);
              }}
              style={{
                borderRadius: '8px',
                padding: '8px 14px',
                fontSize: '12px',
                fontWeight: 500,
                border: 'none',
                cursor: 'pointer',
                transition: 'all 0.15s',
                background: filterStatus === opt.value ? 'var(--bg-card)' : 'transparent',
                color: filterStatus === opt.value ? 'var(--accent-start)' : 'var(--text-secondary)',
                boxShadow: filterStatus === opt.value ? 'var(--shadow-sm)' : 'none',
              }}
            >
              {opt.label}
            </button>
          ))}
        </div>

        {/* Date Range Picker */}
        <RangePicker
          value={dateRange}
          onChange={(dates) => {
            setDateRange(dates);
            setCurrentPage(1);
          }}
          placeholder={['开始日期', '结束日期']}
          style={{
            borderRadius: '12px',
            border: '1px solid var(--border-normal)',
          }}
          suffixIcon={<Calendar size={14} style={{ color: 'var(--text-muted)' }} />}
          allowClear
        />

        {/* Clear Filters */}
        {hasActiveFilters && (
          <button
            onClick={clearFilters}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '4px',
              borderRadius: '8px',
              padding: '8px 12px',
              fontSize: '12px',
              fontWeight: 500,
              border: '1px solid var(--border-normal)',
              background: 'transparent',
              color: 'var(--text-secondary)',
              cursor: 'pointer',
              transition: 'all 0.15s',
            }}
          >
            <X size={12} />
            清除筛选
          </button>
        )}

        {/* Refresh */}
        <button
          onClick={() => loadTasks()}
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            borderRadius: '8px',
            padding: '8px',
            border: '1px solid var(--border-normal)',
            background: 'transparent',
            color: 'var(--text-muted)',
            cursor: 'pointer',
            transition: 'all 0.15s',
          }}
          title="刷新列表"
        >
          <RefreshCw size={14} />
        </button>
      </div>

      {/* ─── Batch Action Bar ─── */}
      {selectedIds.size > 0 && (
        <div
          className="animate-slide-up"
          style={{
            marginBottom: '16px',
            display: 'flex',
            alignItems: 'center',
            gap: '16px',
            borderRadius: '16px',
            border: '1px solid var(--accent-start)',
            background: 'var(--bg-card)',
            padding: '12px 24px',
            boxShadow: '0 4px 16px rgba(91,163,255,0.12)',
          }}
        >
          <span style={{ fontSize: '14px', fontWeight: 500, color: 'var(--accent-start)' }}>
            已选择 {selectedIds.size} 项
          </span>
          <button
            onClick={toggleSelectAll}
            style={{
              fontSize: '12px',
              fontWeight: 500,
              color: 'var(--text-secondary)',
              background: 'none',
              border: 'none',
              cursor: 'pointer',
            }}
          >
            {selectedIds.size === tasks.length ? '取消全选' : '全选本页'}
          </button>
          <div style={{ flex: 1 }} />
          <button
            onClick={showBatchDeleteConfirm}
            disabled={isBatchDeleting}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              borderRadius: '12px',
              padding: '8px 16px',
              fontSize: '12px',
              fontWeight: 500,
              color: 'white',
              background: '#EF4444',
              border: 'none',
              cursor: isBatchDeleting ? 'not-allowed' : 'pointer',
              opacity: isBatchDeleting ? 0.6 : 1,
            }}
          >
            <Trash2 size={14} />
            {isBatchDeleting ? '删除中...' : '批量删除'}
          </button>
          <button
            onClick={() => setSelectedIds(new Set())}
            style={{
              fontSize: '12px',
              fontWeight: 500,
              color: 'var(--text-muted)',
              background: 'none',
              border: 'none',
              cursor: 'pointer',
            }}
          >
            取消
          </button>
        </div>
      )}

      {/* ─── Task Table ─── */}
      <div
        className="animate-slide-up"
        style={{
          display: 'block',
          overflow: 'hidden',
          borderRadius: '16px',
          border: '1px solid var(--border-light)',
          background: 'var(--bg-card)',
          boxShadow: 'var(--shadow-sm)',
          animationDelay: '120ms',
          animationFillMode: 'both',
        }}
      >
        {/* Table Header */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: '40px 3fr 1.5fr 1.5fr 0.8fr 1.5fr 0.8fr',
            alignItems: 'center',
            gap: '16px',
            borderBottom: '1px solid var(--border-light)',
            padding: '14px 24px',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <input
              type="checkbox"
              checked={tasks.length > 0 && selectedIds.size === tasks.length}
              onChange={toggleSelectAll}
              style={{ width: '16px', height: '16px', accentColor: '#5BA3FF', cursor: 'pointer' }}
            />
          </div>
          {['任务名称', '类型', '风险等级', '发现数', '时间', '操作'].map((label, i) => (
            <div
              key={label}
              style={{
                fontSize: '12px',
                fontWeight: 600,
                textTransform: 'uppercase',
                letterSpacing: '0.05em',
                color: 'var(--text-secondary)',
                textAlign: i === 5 ? 'right' : 'left',
              }}
            >
              {label}
            </div>
          ))}
        </div>

        {/* Table Body */}
        {isLoading ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: '60px 0' }}>
            <Spin size="large" />
          </div>
        ) : tasks.length === 0 ? (
          <div
            style={{
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              padding: '64px 0',
              color: 'var(--text-muted)',
            }}
          >
            <Search size={40} style={{ marginBottom: '12px', opacity: 0.3 }} />
            <p style={{ fontSize: '14px', fontWeight: 500 }}>
              {hasActiveFilters ? '未找到匹配的任务' : '暂无历史任务'}
            </p>
            <p style={{ marginTop: '4px', fontSize: '12px' }}>
              {hasActiveFilters ? '请尝试调整搜索条件或筛选器' : '提交一个分析任务开始使用'}
            </p>
          </div>
        ) : (
          <div>
            {tasks.map((task) => {
              const displayName = getTaskDisplayName(task);
              const duration = getTaskDuration(task);
              let severity: string | null = null;
              let vulnCount = 0;
              if (task.result_json) {
                try {
                  const result = JSON.parse(task.result_json);
                  severity = result.severity || null;
                  vulnCount = result.vulnCount || result.vuln_count || 0;
                } catch {
                  // ignore parse error
                }
              }

              return (
                <div
                  key={task.id}
                  style={{
                    display: 'grid',
                    gridTemplateColumns: '40px 3fr 1.5fr 1.5fr 0.8fr 1.5fr 0.8fr',
                    alignItems: 'center',
                    gap: '16px',
                    borderBottom: '1px solid var(--border-light)',
                    padding: '16px 24px',
                    background: selectedIds.has(task.id) ? 'rgba(91,163,255,0.02)' : undefined,
                    transition: 'background 0.15s',
                  }}
                  onMouseEnter={(e) => {
                    if (!selectedIds.has(task.id)) {
                      e.currentTarget.style.background = 'rgba(148,163,184,0.02)';
                    }
                  }}
                  onMouseLeave={(e) => {
                    if (!selectedIds.has(task.id)) {
                      e.currentTarget.style.background = '';
                    }
                  }}
                >
                  {/* Checkbox */}
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    <input
                      type="checkbox"
                      checked={selectedIds.has(task.id)}
                      onChange={() => toggleSelect(task.id)}
                      style={{ width: '16px', height: '16px', accentColor: '#5BA3FF', cursor: 'pointer' }}
                    />
                  </div>
                  {/* Task Name + Status */}
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px', minWidth: 0 }}>
                    <div
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        borderRadius: '12px',
                        flexShrink: 0,
                        width: '36px',
                        height: '36px',
                        background:
                          task.type === 'vulnerability_detection'
                            ? 'rgba(91,163,255,0.08)'
                            : 'rgba(94,234,212,0.08)',
                      }}
                    >
                      {task.type === 'vulnerability_detection' ? (
                        <Code2 size={16} style={{ color: '#5BA3FF' }} />
                      ) : (
                        <Bug size={16} style={{ color: '#5EEAD4' }} />
                      )}
                    </div>
                    <div style={{ minWidth: 0 }}>
                      <div
                        style={{
                          fontSize: '14px',
                          fontWeight: 500,
                          color: 'var(--text-primary)',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                        }}
                      >
                        {displayName}
                      </div>
                      <div style={{ marginTop: '2px', fontSize: '12px', color: 'var(--text-muted)' }}>
                        #{task.id} · {duration}
                      </div>
                    </div>
                  </div>

                  {/* Type */}
                  <div>
                    <span
                      style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '6px',
                        fontSize: '12px',
                        fontWeight: 500,
                        borderRadius: '8px',
                        padding: '4px 8px',
                        background:
                          task.type === 'vulnerability_detection'
                            ? 'rgba(91,163,255,0.06)'
                            : 'rgba(94,234,212,0.06)',
                        color: task.type === 'vulnerability_detection' ? '#5BA3FF' : '#5EEAD4',
                      }}
                    >
                      {task.type === 'vulnerability_detection' ? '代码扫描' : '恶意分析'}
                    </span>
                  </div>

                  {/* Severity + Status */}
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    {getSeverityBadge(severity)}
                    {getStatusBadge(task.status)}
                  </div>

                  {/* Vulnerabilities Count */}
                  <div>
                    {vulnCount > 0 ? (
                      <span
                        style={{
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '4px',
                          fontSize: '12px',
                          fontWeight: 600,
                          color:
                            vulnCount >= 3
                              ? '#EF4444'
                              : vulnCount >= 1
                              ? '#F59E0B'
                              : 'var(--text-secondary)',
                        }}
                      >
                        <AlertTriangle size={12} />
                        {vulnCount}
                      </span>
                    ) : (
                      <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>0</span>
                    )}
                  </div>

                  {/* Time */}
                  <div>
                    <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                      {new Date(task.created_at).toLocaleString('zh-CN', {
                        year: 'numeric',
                        month: '2-digit',
                        day: '2-digit',
                        hour: '2-digit',
                        minute: '2-digit',
                      })}
                    </span>
                  </div>

                  {/* Actions */}
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: '4px' }}>
                    {(task.status === 'done' || task.status === 'failed') && (
                      <button
                        onClick={() => navigate(`/report/${task.id}`)}
                        title="查看报告"
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          borderRadius: '8px',
                          padding: '8px',
                          border: 'none',
                          background: 'transparent',
                          color: 'var(--text-muted)',
                          cursor: 'pointer',
                          transition: 'color 0.15s, background 0.15s',
                        }}
                        onMouseEnter={(e) => {
                          e.currentTarget.style.color = 'var(--accent-start)';
                          e.currentTarget.style.background = 'rgba(91,163,255,0.06)';
                        }}
                        onMouseLeave={(e) => {
                          e.currentTarget.style.color = 'var(--text-muted)';
                          e.currentTarget.style.background = 'transparent';
                        }}
                      >
                        <Eye size={15} />
                      </button>
                    )}
                    {task.status === 'analyzing' && (
                      <button
                        onClick={() => navigate(`/analysis/${task.id}`)}
                        title="查看分析过程"
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          borderRadius: '8px',
                          padding: '8px',
                          border: 'none',
                          background: 'transparent',
                          color: 'var(--text-muted)',
                          cursor: 'pointer',
                          transition: 'color 0.15s, background 0.15s',
                        }}
                        onMouseEnter={(e) => {
                          e.currentTarget.style.color = 'var(--accent-start)';
                          e.currentTarget.style.background = 'rgba(91,163,255,0.06)';
                        }}
                        onMouseLeave={(e) => {
                          e.currentTarget.style.color = 'var(--text-muted)';
                          e.currentTarget.style.background = 'transparent';
                        }}
                      >
                        <Eye size={15} />
                      </button>
                    )}
                    <button
                      onClick={() => showDeleteConfirm(task.id)}
                      title="删除任务"
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        borderRadius: '8px',
                        padding: '8px',
                        border: 'none',
                        background: 'transparent',
                        color: 'var(--text-muted)',
                        cursor: 'pointer',
                        transition: 'color 0.15s, background 0.15s',
                      }}
                      onMouseEnter={(e) => {
                        e.currentTarget.style.color = '#EF4444';
                        e.currentTarget.style.background = 'rgba(239,68,68,0.06)';
                      }}
                      onMouseLeave={(e) => {
                        e.currentTarget.style.color = 'var(--text-muted)';
                        e.currentTarget.style.background = 'transparent';
                      }}
                    >
                      <Trash2 size={15} />
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Pagination */}
      {totalTasks > 0 && (
        <div
          className="animate-slide-up"
          style={{
            marginTop: '20px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: '12px',
            animationDelay: '180ms',
            animationFillMode: 'both',
          }}
        >
          <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            共 {totalTasks} 条记录，第 {currentPage} / {totalPages} 页
          </span>
          <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
            <button
              onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
              disabled={currentPage === 1}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '4px',
                borderRadius: '8px',
                border: '1px solid var(--border-light)',
                padding: '8px 12px',
                fontSize: '12px',
                fontWeight: 500,
                color: 'var(--text-secondary)',
                background: 'transparent',
                cursor: currentPage === 1 ? 'not-allowed' : 'pointer',
                opacity: currentPage === 1 ? 0.4 : 1,
              }}
            >
              <ChevronLeft size={14} />
              上一页
            </button>
            {getPageNumbers(currentPage, totalPages).map((page, idx) =>
              page === '...' ? (
                <span
                  key={`ellipsis-${idx}`}
                  style={{ padding: '0 4px', color: 'var(--text-muted)', fontSize: '12px' }}
                >
                  ...
                </span>
              ) : (
                <button
                  key={page}
                  onClick={() => setCurrentPage(page)}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    borderRadius: '8px',
                    fontSize: '12px',
                    fontWeight: 500,
                    width: '32px',
                    height: '32px',
                    border: 'none',
                    cursor: 'pointer',
                    transition: 'all 0.15s',
                    background: page === currentPage ? 'var(--accent-start)' : 'transparent',
                    color: page === currentPage ? 'white' : 'var(--text-secondary)',
                  }}
                >
                  {page}
                </button>
              )
            )}
            <button
              onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
              disabled={currentPage === totalPages}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '4px',
                borderRadius: '8px',
                border: '1px solid var(--border-light)',
                padding: '8px 12px',
                fontSize: '12px',
                fontWeight: 500,
                color: 'var(--text-secondary)',
                background: 'transparent',
                cursor: currentPage === totalPages ? 'not-allowed' : 'pointer',
                opacity: currentPage === totalPages ? 0.4 : 1,
              }}
            >
              下一页
              <ChevronRight size={14} />
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default History;
