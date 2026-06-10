"""
LLMClient 单元测试 & 集成测试 (pytest)
"""
import json
import sys
import os
from unittest.mock import MagicMock, patch

import pytest
import httpx

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from app.agent.llm import LLMClient, DEFAULT_MODEL

# ── Fixtures ────────────────────────────────────────────────────────
@pytest.fixture
def client():
    return LLMClient(api_key="test-key")


@pytest.fixture
def sample_messages():
    return [
        {"role": "system", "content": "你是安全专家。"},
        {"role": "user", "content": "分析这段代码"},
    ]


@pytest.fixture
def sample_tools():
    return [
        {
            "type": "function",
            "function": {
                "name": "scan_code",
                "description": "扫描代码漏洞",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "code": {"type": "string"},
                        "language": {"type": "string"},
                    },
                    "required": ["code", "language"],
                },
            },
        }
    ]


# ── Helpers ─────────────────────────────────────────────────────────
def _mock_response(content="mock reply", tool_calls=None, usage=None, finish_reason="stop"):
    """构建模拟的 OpenAI 兼容 API 响应 dict。"""
    msg = {"role": "assistant", "content": content}
    if tool_calls:
        msg["tool_calls"] = tool_calls
        msg["content"] = None
    return {
        "choices": [{"message": msg, "finish_reason": finish_reason}],
        "model": DEFAULT_MODEL,
        "usage": usage or {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
    }


def _mock_sse_lines(delta_chunks, tool_call_chunks=None, finish="stop"):
    """生成模拟的 SSE 行列表，模拟流式响应。"""
    lines = []
    for i, d in enumerate(delta_chunks):
        delta = {"content": d}
        if tool_call_chunks and i < len(tool_call_chunks):
            delta["tool_calls"] = tool_call_chunks[i]
        obj = {"choices": [{"delta": delta, "finish_reason": finish if i == len(delta_chunks) - 1 else None}]}
        if i == len(delta_chunks) - 1:
            obj["usage"] = {"prompt_tokens": 10, "completion_tokens": len(delta_chunks), "total_tokens": 10 + len(delta_chunks)}
        lines.append(f"data: {json.dumps(obj, ensure_ascii=False)}")
    return lines


# ====================================================================
# 2.1.1 — 同步调用返回正确格式
# ====================================================================
class TestChatSync:
    def test_returns_correct_structure(self, client, sample_messages):
        """同步调用应返回包含所有必要字段的 dict。"""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _mock_response("结果是安全的")

        with patch.object(httpx.Client, "post", return_value=mock_resp):
            result = client.chat(sample_messages)

        assert result["content"] == "结果是安全的"
        assert result["model"] == DEFAULT_MODEL
        assert result["finish_reason"] == "stop"
        assert result["error"] is None
        assert isinstance(result["tool_calls"], list)
        assert len(result["tool_calls"]) == 0
        assert "prompt_tokens" in result["usage"]
        assert "completion_tokens" in result["usage"]
        assert "total_tokens" in result["usage"]

    def test_accumulates_usage(self, client, sample_messages):
        """同步调用应累加 Token 消耗。"""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _mock_response(
            usage={"prompt_tokens": 5, "completion_tokens": 15, "total_tokens": 20}
        )

        with patch.object(httpx.Client, "post", return_value=mock_resp):
            client.chat(sample_messages)
            client.chat(sample_messages)

        usage = client.total_usage
        assert usage["prompt_tokens"] == 10
        assert usage["completion_tokens"] == 30
        assert usage["total_tokens"] == 40
        assert usage["calls"] == 2

    def test_with_tools_returns_tool_calls(self, client, sample_messages, sample_tools):
        """带 tools 参数时，应正确解析返回的 tool_calls。"""
        tool_calls_raw = [
            {
                "id": "call_abc123",
                "type": "function",
                "function": {
                    "name": "scan_code",
                    "arguments": '{"code": "SELECT * FROM users", "language": "python"}',
                },
            }
        ]
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _mock_response(
            content=None, tool_calls=tool_calls_raw, finish_reason="tool_calls"
        )

        with patch.object(httpx.Client, "post", return_value=mock_resp):
            result = client.chat(sample_messages, tools=sample_tools)

        assert result["finish_reason"] == "tool_calls"
        assert result["content"] is None
        assert len(result["tool_calls"]) == 1
        assert result["tool_calls"][0]["name"] == "scan_code"
        assert result["tool_calls"][0]["arguments"] == {"code": "SELECT * FROM users", "language": "python"}


# ====================================================================
# 2.1.2 — 流式调用能拿到完整结果
# ====================================================================
class TestChatStream:
    def test_stream_yields_complete_text(self, client, sample_messages):
        """流式调用应能收集到完整文本。"""
        sse_lines = _mock_sse_lines(["Hel", "lo", " Wo", "rld", "!"])

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.iter_lines.return_value = iter(sse_lines)
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch.object(httpx.Client, "stream", return_value=mock_resp):
            full_text = ""
            final_finish = None
            for chunk in client.chat_stream(sample_messages):
                full_text += chunk["delta"]
                if chunk["finish_reason"]:
                    final_finish = chunk["finish_reason"]

        assert full_text == "Hello World!"
        assert final_finish == "stop"

    def test_stream_tool_call_deltas(self, client, sample_messages, sample_tools):
        """流式 Function Calling 应正确传递 tool_call_delta。"""
        tc_chunks = [
            [{"id": "call_x", "function": {"name": "scan_code", "arguments": ""}}],
            [{"function": {"arguments": '{"code": "bad"'}}],
            [{"function": {"arguments": '}'}}],
        ]
        sse_lines = _mock_sse_lines(["", "", ""], tool_call_chunks=tc_chunks, finish="tool_calls")

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.iter_lines.return_value = iter(sse_lines)
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch.object(httpx.Client, "stream", return_value=mock_resp):
            tool_id = ""
            tool_name = ""
            tool_args = ""
            for chunk in client.chat_stream(sample_messages, tools=sample_tools):
                tc = chunk["tool_call_delta"]
                if tc:
                    if tc["id"]: tool_id = tc["id"]
                    if tc["name"]: tool_name = tc["name"]
                    tool_args += tc["arguments_fragment"]

        assert tool_id == "call_x"
        assert tool_name == "scan_code"
        assert "bad" in tool_args

    def test_stream_handles_error(self, client, sample_messages):
        """流式调用网络异常时应 yield 错误 chunk。"""
        with patch.object(httpx.Client, "stream", side_effect=httpx.ConnectError("拒绝连接")):
            chunks = list(client.chat_stream(sample_messages))

        assert len(chunks) == 1
        assert chunks[0]["finish_reason"] == "error"
        assert "网络连接失败" in chunks[0]["error"]


# ====================================================================
# Function Calling 解析
# ====================================================================
class TestParseToolCalls:
    def test_empty_list(self):
        result = LLMClient._parse_tool_calls([])
        assert result == []

    def test_single_call(self):
        raw = [{"id": "c1", "function": {"name": "f1", "arguments": '{"a": 1}'}}]
        result = LLMClient._parse_tool_calls(raw)
        assert result == [{"id": "c1", "name": "f1", "arguments": {"a": 1}}]

    def test_invalid_json_arguments(self):
        raw = [{"id": "c1", "function": {"name": "f1", "arguments": "not json"}}]
        result = LLMClient._parse_tool_calls(raw)
        assert result[0]["arguments"] == "not json"  # 保留原始字符串


# ====================================================================
# Token 估算 (2.1.5)
# ====================================================================
class TestTokenEstimation:
    def test_empty_string(self):
        assert LLMClient.estimate_tokens("") == 0

    def test_pure_english(self):
        est = LLMClient.estimate_tokens("hello world")
        assert 2 <= est <= 4  # ~3 tokens

    def test_pure_chinese(self):
        est = LLMClient.estimate_tokens("你好世界")
        assert 2 <= est <= 5  # ~3 tokens

    def test_messages_estimate(self):
        msgs = [
            {"role": "system", "content": "你是助手。"},
            {"role": "user", "content": "你好"},
        ]
        est = LLMClient.estimate_messages_tokens(msgs)
        assert est > 0
        # 每条消息至少有其估算 + role 开销
        assert est > LLMClient.estimate_tokens("你是助手。") + LLMClient.estimate_tokens("你好")


# ====================================================================
# Token 截断
# ====================================================================
class TestTruncation:
    def test_no_truncation_when_under_limit(self, client):
        msgs = [{"role": "user", "content": "hello"}]
        result = client._truncate_messages(msgs)
        assert len(result) == 1

    def test_preserves_system_message(self, client):
        """截断后 system 消息必须保留。"""
        client.max_input_tokens = 5  # 极小限制
        msgs = [
            {"role": "system", "content": "你是助手。"},
            {"role": "user", "content": "这条消息很长" * 100},
            {"role": "user", "content": "另一条" * 100},
        ]
        result = client._truncate_messages(msgs)
        assert len(result) >= 1
        assert result[0]["role"] == "system"


# ====================================================================
# 错误处理 (2.1.4)
# ====================================================================
class TestErrorHandling:
    def test_network_error_returns_error_response(self, client, sample_messages):
        """网络错误应返回统一错误格式而不是抛异常。"""
        with patch.object(httpx.Client, "post", side_effect=httpx.ConnectError("拒绝连接")):
            result = client.chat(sample_messages)

        assert result["finish_reason"] == "error"
        assert result["error"] is not None
        assert "网络连接失败" in result["error"]
        assert isinstance(result["tool_calls"], list)

    def test_http_4xx_returns_error(self, client, sample_messages):
        """4xx 不应重试，直接返回错误。"""
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Unauthorized", request=MagicMock(), response=mock_resp
        )

        with patch.object(httpx.Client, "post", return_value=mock_resp):
            result = client.chat(sample_messages)

        assert result["finish_reason"] == "error"
        assert "401" in result["error"]

    def test_retry_on_5xx(self, client, sample_messages):
        """5xx 应触发重试。"""
        fail_resp = MagicMock()
        fail_resp.status_code = 500
        fail_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Server Error", request=MagicMock(), response=fail_resp
        )

        success_resp = MagicMock()
        success_resp.status_code = 200
        success_resp.json.return_value = _mock_response("最终成功")

        # 前两次 500，第三次成功
        with patch.object(httpx.Client, "post", side_effect=[fail_resp, fail_resp, success_resp]):
            result = client.chat(sample_messages)

        assert result["finish_reason"] == "stop"
        assert result["content"] == "最终成功"


# ====================================================================
# 集成测试（需要真实 API，标记为 skip 若无 key）
# ====================================================================
NEEDS_API = pytest.mark.skipif(
    not os.getenv("DASHSCOPE_API_KEY"),
    reason="需要 DASHSCOPE_API_KEY 环境变量",
)


@NEEDS_API
class TestIntegration:
    def test_chat_returns_valid_format(self):
        """集成: 同步调用返回正确格式。"""
        from dotenv import load_dotenv
        load_dotenv()
        client = LLMClient()
        result = client.chat([
            {"role": "user", "content": "回复OK即可"},
        ])
        assert result["finish_reason"] == "stop"
        assert result["content"] is not None
        assert result["error"] is None
        assert result["usage"]["total_tokens"] > 0

    def test_chat_stream_collects_complete_response(self):
        """集成: 流式调用能收集到完整结果。"""
        from dotenv import load_dotenv
        load_dotenv()
        client = LLMClient()
        full = ""
        for chunk in client.chat_stream([
            {"role": "user", "content": "说3个词：苹果 香蕉 橙子"},
        ]):
            full += chunk["delta"]
        assert "苹果" in full
        assert "橙子" in full

    def test_cumulative_usage_tracks_calls(self):
        """集成: 多次调用后累计统计正确。"""
        from dotenv import load_dotenv
        load_dotenv()
        client = LLMClient()
        client.reset_usage()
        client.chat([{"role": "user", "content": "回复'好'"}])
        client.chat([{"role": "user", "content": "回复'行'"}])
        assert client.total_usage["calls"] == 2
        assert client.total_usage["total_tokens"] > 0
