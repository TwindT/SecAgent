import axios, { AxiosError } from 'axios';
import type { InternalAxiosRequestConfig } from 'axios';

// 创建 axios 实例
const apiClient = axios.create({
  baseURL: '/api',
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// 请求拦截器
apiClient.interceptors.request.use(
  (config: InternalAxiosRequestConfig) => {
    // 后续可在此添加 token 等认证信息
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// 响应拦截器
apiClient.interceptors.response.use(
  (response) => {
    return response;
  },
  (error: AxiosError) => {
    const status = error.response?.status;
    const data: any = error.response?.data;

    if (status === 404) {
      console.error('资源不存在:', data?.detail || error.message);
    } else if (status === 400) {
      console.error('请求参数错误:', data?.detail || error.message);
    } else if (status === 413) {
      console.error('文件大小超出限制');
      // 将413错误转为用户友好的错误消息
      const friendlyError = new Error('文件大小超出 50MB 限制，请选择更小的文件');
      return Promise.reject(friendlyError);
    } else if (status === 429) {
      console.error('请求过于频繁，请稍后重试');
    } else if (!error.response) {
      console.error('网络错误，请检查网络连接');
      const friendlyError = new Error('网络连接失败，请检查网络后重试');
      return Promise.reject(friendlyError);
    } else {
      console.error('请求失败:', error.message);
    }

    return Promise.reject(error);
  }
);

// ==================== 类型定义 ====================

export type TaskType = 'vulnerability_detection' | 'malware_analysis';
export type TaskStatus = 'pending' | 'analyzing' | 'done' | 'failed';

export interface CreateTaskParams {
  type: TaskType;
  name?: string;
  input_content?: string;
  input_path?: string;
}

export interface CreateTaskResponse {
  task_id: number;
  message: string;
}

export interface AnalysisStep {
  id: number;
  task_id: number;
  step_num: number;
  thought?: string;
  action?: string;
  observation?: string;
  created_at: string;
}

export interface TaskResponse {
  id: number;
  name?: string;
  type: TaskType;
  status: TaskStatus;
  input_path?: string;
  input_content?: string;
  result_json?: string;
  analysis_steps?: AnalysisStep[];
  created_at: string;
  updated_at: string;
}

export interface TaskListResponse {
  total: number;
  tasks: TaskResponse[];
}

export interface TaskListParams {
  page?: number;
  page_size?: number;
  type?: TaskType;
  status?: TaskStatus;
  search?: string;
  date_from?: string;
  date_to?: string;
}

export interface SendMessageParams {
  message: string;
}

export interface SendMessageResponse {
  reply: string;
  task_id: number;
}

export interface ConversationResponse {
  id: number;
  task_id: number;
  role: 'user' | 'assistant';
  content: string;
  created_at: string;
}

export interface UploadResponse {
  filename: string;
  file_hash: string;
  md5_hash: string;
  size: number;
  path: string;
  content_type_detected: string;
}

export interface QueueStatus {
  pending_count: number;
  analyzing_count: number;
  max_concurrent: number;
  celery_active?: number;
  celery_reserved?: number;
}

export interface StatsResponse {
  total_tasks: number;
  today_tasks: number;
  high_severity_tasks: number;
  avg_duration: string;
  recent_tasks: TaskResponse[];
  tasks_by_type: Array<{ type: string; count: number }>;
  tasks_by_severity: Array<{ severity: string; count: number }>;
  tasks_by_day: Array<{ date: string; count: number }>;
}

// ==================== API 方法 ====================

/** 创建分析任务 */
export const createTask = (params: CreateTaskParams) =>
  apiClient.post<CreateTaskResponse>('/tasks', params);

/** 获取任务列表 */
export const getTaskList = (params?: TaskListParams) =>
  apiClient.get<TaskListResponse>('/tasks', { params });

/** 获取任务详情 */
export const getTask = (taskId: number) =>
  apiClient.get<TaskResponse>(`/tasks/${taskId}`);

/** 获取任务分析步骤 */
export const getTaskSteps = (taskId: number) =>
  apiClient.get<AnalysisStep[]>(`/tasks/${taskId}/steps`);

/** 发送追问消息（超时60秒，LLM响应可能较慢） */
export const sendMessage = (taskId: number, params: SendMessageParams) =>
  apiClient.post<SendMessageResponse>(`/tasks/${taskId}/chat`, params, {
    timeout: 60000,
  });

/** 获取对话历史 */
export const getConversations = (taskId: number) =>
  apiClient.get<ConversationResponse[]>(`/tasks/${taskId}/conversations`);

/** 下载 PDF 报告 */
export const downloadPdfReport = (taskId: number) =>
  apiClient.get(`/tasks/${taskId}/report/pdf`, { responseType: 'blob' });

/** 下载 Markdown 报告 */
export const downloadMdReport = (taskId: number) =>
  apiClient.get(`/tasks/${taskId}/report/md`, { responseType: 'text' });

/** 上传文件 */
export const uploadFile = (file: File) => {
  const formData = new FormData();
  formData.append('file', file);
  return apiClient.post<UploadResponse>('/upload', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
    timeout: 120000, // 文件上传超时 2 分钟
  });
};

/** 获取队列状态 */
export const getQueueStatus = () =>
  apiClient.get<QueueStatus>('/tasks/queue/status');

/** 获取仪表盘统计数据 */
export const fetchStats = () =>
  apiClient.get<StatsResponse>('/stats');

/** 删除任务 */
export const deleteTask = (taskId: number) =>
  apiClient.delete(`/tasks/${taskId}`);

export default apiClient;
