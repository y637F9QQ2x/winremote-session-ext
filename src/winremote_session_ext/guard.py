"""Host and Origin validation for HTTP and WebSocket requests (DNS rebinding,
cross-site requests from a browser).

A plain ASGI middleware, so it does not buffer streamed (SSE) responses.
It runs before upstream's authentication middleware.
"""

from __future__ import annotations

import json

from .policy import host_allowed, origin_allowed

# RFC 6455 close code 1008, "policy violation".
_WS_POLICY_VIOLATION = 1008


def _header(scope, name: bytes) -> str | None:
    for key, value in scope.get("headers") or ():
        if key.lower() == name:
            return value.decode("latin-1")
    return None


class HostOriginGuard:
    def __init__(self, app, allowed_host_names: frozenset[str], allowed_origins: frozenset[str]):
        self.app = app
        self.allowed_host_names = allowed_host_names
        self.allowed_origins = allowed_origins

    def _problem(self, scope) -> tuple[int, str] | None:
        if not host_allowed(_header(scope, b"host"), self.allowed_host_names):
            return 421, "Host header not allowed"
        if not origin_allowed(_header(scope, b"origin"), self.allowed_origins):
            return 403, "Origin not allowed"
        return None

    async def __call__(self, scope, receive, send):
        kind = scope.get("type")
        if kind == "lifespan":
            await self.app(scope, receive, send)
            return
        if kind not in ("http", "websocket"):
            raise RuntimeError(f"HostOriginGuard: unsupported ASGI scope type {kind!r}")
        problem = self._problem(scope)
        if problem is None:
            await self.app(scope, receive, send)
        elif kind == "http":
            await _deny(send, *problem)
        else:
            # Closing before the handshake is accepted refuses the WebSocket connection.
            await send({"type": "websocket.close", "code": _WS_POLICY_VIOLATION})


async def _deny(send, status: int, message: str) -> None:
    body = json.dumps({"error": message}).encode("ascii")
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})
