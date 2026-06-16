import { useEffect, useRef, useCallback, useState } from 'react';

// WebSocket 消息类型，与后端约定一致
export type WSMessageType = 'thought' | 'action' | 'observation' | 'done' | 'error' | 'connected' | 'ping' | 'heartbeat';

export interface WSMessage {
  type: WSMessageType;
  data: Record<string, unknown>;
}

/**
 * 安全地解析可能是字符串的字段
 * 如果字段是字符串且看起来像 JSON，则尝试解析
 */
function safeParseField(value: unknown): unknown {
  if (typeof value === 'string') {
    const trimmed = value.trim();
    if ((trimmed.startsWith('{') && trimmed.endsWith('}')) ||
        (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
      try {
        return JSON.parse(trimmed);
      } catch {
        // 解析失败，返回原始值
      }
    }
  }
  return value;
}

/**
 * 确保 data 对象中的关键字段被正确解析
 * 后端可能将 results/observations 等字段序列化为字符串
 */
export function normalizeWSMessage(msg: WSMessage): WSMessage {
  if (!msg.data || typeof msg.data !== 'object') {
    return msg;
  }

  const normalizedData: Record<string, unknown> = { ...msg.data };

  // 对可能的 JSON 字符串字段进行解析
  const jsonFields = ['results', 'observations', 'content', 'detail'];
  for (const field of jsonFields) {
    if (field in normalizedData) {
      normalizedData[field] = safeParseField(normalizedData[field]);
    }
  }

  return {
    ...msg,
    data: normalizedData,
  };
}

export interface UseWebSocketOptions {
  /** 自动重连，默认 true */
  autoReconnect?: boolean;
  /** 重连间隔(ms)，默认 3000 */
  reconnectInterval?: number;
  /** 最大重连次数，默认 5 */
  maxReconnectAttempts?: number;
  /** 收到消息回调 */
  onMessage?: (msg: WSMessage) => void;
  /** 连接成功回调 */
  onOpen?: () => void;
  /** 连接关闭回调 */
  onClose?: () => void;
  /** 连接错误回调 */
  onError?: (error: Event) => void;
}

export interface UseWebSocketReturn {
  /** 当前连接状态 */
  readyState: number;
  /** 收到的所有消息列表 */
  messages: WSMessage[];
  /** 最后一条消息 */
  lastMessage: WSMessage | null;
  /** 手动发送消息 */
  sendMessage: (data: string | object) => void;
  /** 手动断开连接 */
  disconnect: () => void;
  /** 手动重连 */
  reconnect: () => void;
  /** 是否正在重连 */
  isReconnecting: boolean;
}

/**
 * WebSocket 连接 Hook
 * - 自动连接 /ws/{taskId}
 * - 自动响应心跳 pong
 * - 支持自动重连
 * - done/error 消息后不再重连
 */
export function useWebSocket(
  taskId: string | undefined,
  options: UseWebSocketOptions = {}
): UseWebSocketReturn {
  const {
    autoReconnect = true,
    reconnectInterval = 3000,
    maxReconnectAttempts = 5,
    onMessage,
    onOpen,
    onClose,
    onError,
  } = options;

  const [readyState, setReadyState] = useState<number>(WebSocket.CONNECTING);
  const [messages, setMessages] = useState<WSMessage[]>([]);
  const [lastMessage, setLastMessage] = useState<WSMessage | null>(null);
  const [isReconnecting, setIsReconnecting] = useState(false);

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectCountRef = useRef(0);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const closedByUserRef = useRef(false);
  const taskDoneRef = useRef(false);

  // 构建 WebSocket URL
  const getWsUrl = useCallback(() => {
    if (!taskId) return null;
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host;
    return `${protocol}//${host}/ws/${taskId}`;
  }, [taskId]);

  // 发送消息
  const sendMessage = useCallback((data: string | object) => {
    const ws = wsRef.current;
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(typeof data === 'string' ? data : JSON.stringify(data));
    }
  }, []);

  // 清理重连定时器
  const clearReconnectTimer = useCallback(() => {
    if (reconnectTimerRef.current) {
      clearTimeout(reconnectTimerRef.current);
      reconnectTimerRef.current = null;
    }
  }, []);

  // 断开连接
  const disconnect = useCallback(() => {
    closedByUserRef.current = true;
    clearReconnectTimer();
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
  }, [clearReconnectTimer]);

  // 创建连接
  const connect = useCallback(() => {
    const url = getWsUrl();
    if (!url) return;

    // 关闭旧连接
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }

    closedByUserRef.current = false;
    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => {
      setReadyState(WebSocket.OPEN);
      setIsReconnecting(false);
      reconnectCountRef.current = 0;
      onOpen?.();
    };

    ws.onmessage = (event: MessageEvent) => {
      try {
        const msg: WSMessage = JSON.parse(event.data);

        // 响应心跳 ping
        if (msg.type === 'ping' || msg.type === 'heartbeat') {
          ws.send(JSON.stringify({ type: 'pong' }));
          return;
        }

        setMessages((prev) => [...prev, msg]);
        setLastMessage(msg);
        onMessage?.(msg);

        // done 或 error 后标记任务结束，不再重连
        if (msg.type === 'done' || msg.type === 'error') {
          taskDoneRef.current = true;
        }
      } catch {
        // 非 JSON 消息，忽略
      }
    };

    ws.onclose = () => {
      setReadyState(WebSocket.CLOSED);
      wsRef.current = null;
      onClose?.();

      // 自动重连逻辑
      if (
        autoReconnect &&
        !closedByUserRef.current &&
        !taskDoneRef.current &&
        reconnectCountRef.current < maxReconnectAttempts
      ) {
        reconnectCountRef.current += 1;
        setIsReconnecting(true);
        reconnectTimerRef.current = setTimeout(() => {
          connect();
        }, reconnectInterval);
      }
    };

    ws.onerror = (event) => {
      setReadyState(WebSocket.CLOSED);
      onError?.(event);
    };
  }, [getWsUrl, autoReconnect, reconnectInterval, maxReconnectAttempts, onMessage, onOpen, onClose, onError]);

  // 重连
  const reconnect = useCallback(() => {
    reconnectCountRef.current = 0;
    taskDoneRef.current = false;
    connect();
  }, [connect]);

  // taskId 变化时建立新连接
  useEffect(() => {
    taskDoneRef.current = false;
    reconnectCountRef.current = 0;
    setMessages([]);
    setLastMessage(null);

    if (taskId) {
      connect();
    }

    return () => {
      disconnect();
    };
  }, [taskId]); // eslint-disable-line react-hooks/exhaustive-deps

  return {
    readyState,
    messages,
    lastMessage,
    sendMessage,
    disconnect,
    reconnect,
    isReconnecting,
  };
}

export default useWebSocket;
