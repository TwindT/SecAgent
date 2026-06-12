"""基于滑动窗口的内存速率限制中间件"""

import time
import threading
from collections import defaultdict

from starlette.responses import JSONResponse


class RateLimitMiddleware:
    """ASGI 中间件：按客户端 IP 限制请求速率。

    参数:
        max_requests: 窗口内允许的最大请求数 (默认 60)
        window:       时间窗口秒数 (默认 60)
    """

    def __init__(self, app, max_requests: int = 60, window: int = 60):
        self.app = app
        self.max_requests = max_requests
        self.window = window
        self._lock = threading.Lock()
        self._clients: dict[str, list[float]] = defaultdict(list)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # 跳过 CORS 预检请求
        if scope.get("method") == "OPTIONS":
            await self.app(scope, receive, send)
            return

        client_ip = self._get_client_ip(scope)
        now = time.time()

        with self._lock:
            cutoff = now - self.window
            requests = [t for t in self._clients[client_ip] if t > cutoff]
            self._clients[client_ip] = requests

            if len(requests) >= self.max_requests:
                response = JSONResponse(
                    {"detail": "请求过于频繁，请稍后重试"}, status_code=429
                )
                await response(scope, receive, send)
                return

            self._clients[client_ip].append(now)

        await self.app(scope, receive, send)

    @staticmethod
    def _get_client_ip(scope) -> str:
        """从 ASGI scope 中提取客户端真实 IP。"""
        headers = scope.get("headers", [])
        for name, value in headers:
            if name == b"x-forwarded-for":
                return value.decode().split(",")[0].strip()
        client = scope.get("client")
        if client:
            return client[0]
        return "unknown"
