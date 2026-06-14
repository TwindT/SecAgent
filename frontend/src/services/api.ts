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
    } else if (status === 429) {
      console.error('请求过于频繁，请稍后重试');
    } else if (!error.response) {
      console.error('网络错误，请检查网络连接');
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
}

export interface SendMessageParams {
  message: string;
}

export interface SendMessageResponse {
  reply: string;
  task_id: number;
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
}

export interface StatsTask {
  id: string;
  type: 'code_scan' | 'malware_analysis';
  status: 'pending' | 'analyzing' | 'done' | 'failed';
  name: string;
  inputPath: string | null;
  inputContent: string | null;
  language: string | null;
  resultJson: string | null;
  severity: 'high' | 'medium' | 'low' | 'info' | null;
  vulnCount: number;
  duration: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface StatsResponse {
  totalTasks: number;
  todayTasks: number;
  highSeverityTasks: number;
  avgDuration: string;
  recentTasks: StatsTask[];
  tasksByType: Array<{ type: string; count: number }>;
  tasksBySeverity: Array<{ severity: string; count: number }>;
  tasksByDay: Array<{ date: string; count: number }>;
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

/** 发送追问消息 */
export const sendMessage = (taskId: number, params: SendMessageParams) =>
  apiClient.post<SendMessageResponse>(`/tasks/${taskId}/chat`, params);

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

/** 触发任务分析 */
export const triggerAnalysis = (taskId: number) =>
  apiClient.post(`/tasks/${taskId}/analyze`);

export default apiClient;
