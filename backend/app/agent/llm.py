"""
LLM API 封装模块 - DashScope (阿里百练) OpenAI 兼容接口
"""
import os
import re
import time
import json
import logging
from typing import Any, Generator, Optional

import httpx
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

DASHSCOPE_API_KEY = os.getenv("DASHSCOPE_API_KEY")
DEFAULT_BASE_URL = "https://dashscope.aliyuncs.com/compatible-mode/v1"
DEFAULT_MODEL = "qwen3.6-plus"

# 可重试的异常类型
RETRYABLE_EXCEPTIONS = (
    httpx.TimeoutException,
    httpx.NetworkError,
    httpx.ConnectError,
    httpx.RemoteProtocolError,
)


class LLMClient:
    """DashScope LLM 客户端，封装同步/流式调用、Function Calling、错误处理"""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = DEFAULT_MODEL,
        base_url: str = DEFAULT_BASE_URL,
        max_tokens: int = 4096,
        temperature: float = 0.1,
        timeout: float = 60.0,
        max_retries: int = 3,
        max_input_tokens: int = 6000,
    ):
        self.api_key = api_key or DASHSCOPE_API_KEY
        if not self.api_key:
            raise ValueError("DASHSCOPE_API_KEY 未设置，请在 .env 文件中配置或传入 api_key 参数")

        self.model = model
        self.base_url = base_url.rstrip("/")
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.timeout = timeout
        self.max_retries = max_retries
        self.max_input_tokens = max_input_tokens

        # 累计 Token 消耗
        self._cumulative_usage: dict[str, int] = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0, "calls": 0}

        self._headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    # ------------------------------------------------------------------
    # Token 估算（2.1.5）
    # ------------------------------------------------------------------
    # CJK 统一表意文字区间
    _CJK_RE = re.compile(r"[一-鿿㐀-䶿豈-﫿]")

    @classmethod
    def estimate_tokens(cls, text: str) -> int:
        """估算文本的 Token 数量。

        中文 (CJK) 约 1.5 字符/token，英文/数字约 4 字符/token。
        返回向上取整的估算值。
        """
        if not text:
            return 0
        cjk_chars = len(cls._CJK_RE.findall(text))
        other_chars = len(text) - cjk_chars
        estimated = (cjk_chars / 1.3) + (other_chars / 4.0)
        return max(1, int(estimated + 0.5))

    @classmethod
    def estimate_messages_tokens(cls, messages: list[dict]) -> int:
        """估算消息列表的总 Token 数（含 role 开销）。"""
        total = 0
        for m in messages:
            content = str(m.get("content", ""))
            total += cls.estimate_tokens(content)
            # 每条消息的 role 和格式开销约 4 token
            total += 4
        return total

    def _accumulate_usage(self, usage: dict) -> None:
        """将单次调用用量累加到总数。"""
        if usage:
            self._cumulative_usage["prompt_tokens"] += usage.get("prompt_tokens", 0)
            self._cumulative_usage["completion_tokens"] += usage.get("completion_tokens", 0)
            self._cumulative_usage["total_tokens"] += usage.get("total_tokens", 0)
            self._cumulative_usage["calls"] += 1

    @property
    def total_usage(self) -> dict:
        """返回累计 Token 消耗统计。"""
        return dict(self._cumulative_usage)

    def reset_usage(self) -> None:
        """重置累计 Token 统计。"""
        self._cumulative_usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0, "calls": 0}

    # ------------------------------------------------------------------
    # 内部工具方法
    # ------------------------------------------------------------------
    def _build_payload(self, messages: list[dict], tools: Optional[list[dict]], tool_choice: str, stream: bool) -> dict:
        """构建请求 body，自动处理 Token 超限截断。"""
        messages = self._truncate_messages(messages)

        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "stream": stream,
        }

        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = tool_choice

        return payload

    def _truncate_messages(self, messages: list[dict]) -> list[dict]:
        """Token 超限截断：保留 system 消息，从最旧的非 system 消息开始丢弃。"""
        estimated = self.estimate_messages_tokens(messages)

        if estimated <= self.max_input_tokens:
            return messages

        logger.warning("消息 Token 估算 %d 超过上限 %d，执行截断", estimated, self.max_input_tokens)

        system_msgs = [m for m in messages if m["role"] == "system"]
        others = [m for m in messages if m["role"] != "system"]

        while others:
            current = system_msgs + others
            if self.estimate_messages_tokens(current) <= self.max_input_tokens:
                break
            others.pop(0)

        return system_msgs + others

    def _post_with_retry(self, payload: dict) -> httpx.Response:
        """HTTP POST 带重试：最多 3 次，指数退避 1s/2s/4s。

        可重试：超时、网络错误、连接错误、5xx 服务端错误
        不重试：4xx 客户端错误（401 鉴权失败、400 参数错误等）
        """
        last_error: Optional[Exception] = None

        for attempt in range(self.max_retries + 1):  # 1 次初始 + N 次重试
            try:
                client = httpx.Client(timeout=self.timeout)
                response = client.post(
                    f"{self.base_url}/chat/completions",
                    headers=self._headers,
                    json=payload,
                )
                # 5xx 重试，4xx 直接抛
                if response.status_code >= 500:
                    response.raise_for_status()
                if response.status_code >= 400:
                    # 4xx 不重试，直接返回让调用方处理
                    response.raise_for_status()
                return response

            except RETRYABLE_EXCEPTIONS as e:
                last_error = e
                if attempt < self.max_retries:
                    wait = 2 ** attempt
                    logger.warning("LLM 调用失败 (尝试 %d/%d): %s，%ds 后重试", attempt + 1, self.max_retries + 1, e, wait)
                    time.sleep(wait)
            except httpx.HTTPStatusError as e:
                if e.response.status_code >= 500 and attempt < self.max_retries:
                    last_error = e
                    wait = 2 ** attempt
                    logger.warning("服务端错误 %d (尝试 %d/%d)，%ds 后重试", e.response.status_code, attempt + 1, self.max_retries + 1, wait)
                    time.sleep(wait)
                else:
                    raise

        raise last_error  # type: ignore[return-value]

    def _stream_with_retry(self, payload: dict) -> Generator[str, None, None]:
        """流式 POST 带重试，逐行 yield SSE 数据。"""
        last_error: Optional[Exception] = None

        for attempt in range(self.max_retries + 1):
            try:
                client = httpx.Client(timeout=self.timeout)
                with client.stream(
                    "POST",
                    f"{self.base_url}/chat/completions",
                    headers=self._headers,
                    json=payload,
                ) as response:
                    if response.status_code >= 400:
                        response.raise_for_status()
                    for line in response.iter_lines():
                        yield line
                return  # 成功完成

            except RETRYABLE_EXCEPTIONS as e:
                last_error = e
                if attempt < self.max_retries:
                    wait = 2 ** attempt
                    logger.warning("流式调用失败 (尝试 %d/%d): %s，%ds 后重试", attempt + 1, self.max_retries + 1, e, wait)
                    time.sleep(wait)
            except httpx.HTTPStatusError as e:
                if e.response.status_code >= 500 and attempt < self.max_retries:
                    last_error = e
                    wait = 2 ** attempt
                    logger.warning("服务端错误 %d (尝试 %d/%d)，%ds 后重试", e.response.status_code, attempt + 1, self.max_retries + 1, wait)
                    time.sleep(wait)
                else:
                    raise

        raise last_error  # type: ignore[return-value]

    @staticmethod
    def _error_response(error_msg: str) -> dict:
        """统一错误响应格式。"""
        return {
            "content": None,
            "tool_calls": [],
            "model": "",
            "usage": {},
            "finish_reason": "error",
            "error": error_msg,
        }

    # ------------------------------------------------------------------
    # 2.1.1 同步调用
    # ------------------------------------------------------------------
    def chat(
        self,
        messages: list[dict],
        tools: Optional[list[dict]] = None,
        tool_choice: str = "auto",
    ) -> dict:
        """同步调用 LLM，传入 messages，返回完整 response dict。

        参数:
            messages:   消息列表 [{"role": "system"|"user"|"assistant", "content": ...}]
            tools:      工具 Schema 列表（Function Calling），None 表示不启用
            tool_choice: "auto" | "none" | "required"

        返回格式:
        {
            "content": str | None,
            "tool_calls": [{"id": str, "name": str, "arguments": dict}],
            "model": str,
            "usage": {"prompt_tokens": int, "completion_tokens": int, "total_tokens": int},
            "finish_reason": str,   # stop / length / tool_calls / error
            "error": str | None,    # 仅在出错时存在
        }
        """
        try:
            payload = self._build_payload(messages, tools, tool_choice, stream=False)
            response = self._post_with_retry(payload)
            raw = response.json()
        except RETRYABLE_EXCEPTIONS as e:
            logger.error("LLM 同步调用网络异常: %s", e)
            return self._error_response(f"网络连接失败（已重试 {self.max_retries} 次）: {e}")
        except httpx.HTTPStatusError as e:
            logger.error("LLM API 错误 %d: %s", e.response.status_code, e)
            return self._error_response(f"API 错误 ({e.response.status_code})")
        except Exception as e:
            logger.error("LLM 同步调用未知异常: %s", e)
            return self._error_response(f"未知错误: {e}")

        choice = raw["choices"][0]
        message = choice["message"]
        usage = raw.get("usage", {})

        # 累计 Token 消耗
        self._accumulate_usage(usage)

        return {
            "content": message.get("content"),
            "tool_calls": self._parse_tool_calls(message.get("tool_calls", [])),
            "model": raw.get("model", self.model),
            "usage": usage,
            "finish_reason": choice.get("finish_reason", "stop"),
            "error": None,
        }

    @staticmethod
    def _parse_tool_calls(raw_calls: list[dict]) -> list[dict]:
        """将 API 返回的 tool_calls 解析为统一格式。"""
        parsed = []
        for tc in raw_calls:
            func = tc.get("function", {})
            try:
                args = json.loads(func.get("arguments", "{}"))
            except json.JSONDecodeError:
                args = func.get("arguments", "{}")
            parsed.append({
                "id": tc.get("id", ""),
                "name": func.get("name", ""),
                "arguments": args,
            })
        return parsed

    # ------------------------------------------------------------------
    # 2.1.2 流式调用
    # ------------------------------------------------------------------
    def chat_stream(
        self,
        messages: list[dict],
        tools: Optional[list[dict]] = None,
        tool_choice: str = "auto",
    ) -> Generator[dict, None, None]:
        """流式调用 LLM，传入 messages，yield 每个 token/tool_call 增量 chunk。

        参数:
            messages:   消息列表
            tools:      工具 Schema 列表，None 表示不启用
            tool_choice: "auto" | "none" | "required"

        每个 chunk 格式:
        {
            "delta": str,
            "tool_call_delta": dict | None,
            "finish_reason": str | None,
            "usage": dict | None,
            "error": str | None,     # 仅在出错时存在
        }
        """
        try:
            payload = self._build_payload(messages, tools, tool_choice, stream=True)
            lines = self._stream_with_retry(payload)

            for line in lines:
                if not line or line.startswith(":"):
                    continue
                if line == "data: [DONE]":
                    break
                if line.startswith("data: "):
                    raw = json.loads(line[6:])
                    delta = raw["choices"][0].get("delta", {})
                    finish = raw["choices"][0].get("finish_reason")

                    tool_call_delta = None
                    raw_calls = delta.get("tool_calls", [])
                    if raw_calls:
                        tc = raw_calls[0]
                        tool_call_delta = {
                            "id": tc.get("id"),
                            "name": tc.get("function", {}).get("name"),
                            "arguments_fragment": tc.get("function", {}).get("arguments", ""),
                        }

                    yield {
                        "delta": delta.get("content", ""),
                        "tool_call_delta": tool_call_delta,
                        "finish_reason": finish,
                        "usage": raw.get("usage"),
                        "error": None,
                    }
        except RETRYABLE_EXCEPTIONS as e:
            logger.error("LLM 流式调用网络异常: %s", e)
            yield {"delta": "", "tool_call_delta": None, "finish_reason": "error", "usage": None, "error": f"网络连接失败（已重试 {self.max_retries} 次）: {e}"}
        except httpx.HTTPStatusError as e:
            logger.error("LLM 流式 API 错误 %d: %s", e.response.status_code, e)
            yield {"delta": "", "tool_call_delta": None, "finish_reason": "error", "usage": None, "error": f"API 错误 ({e.response.status_code})"}
        except Exception as e:
            logger.error("LLM 流式调用未知异常: %s", e)
            yield {"delta": "", "tool_call_delta": None, "finish_reason": "error", "usage": None, "error": f"未知错误: {e}"}
