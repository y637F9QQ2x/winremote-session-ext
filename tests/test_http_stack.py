"""The real middleware stack from upstream's CLI, driven in memory through
httpx2's ASGI transport. No server is started and no port is opened: the
requests go straight to the ASGI application object."""

import asyncio
import json

import pytest

from winremote_session_ext import policy
from winremote_session_ext.guard import HostOriginGuard

httpx = pytest.importorskip("httpx2")  # installed with winremote-mcp

KEY = "k" * 40
INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "test_http_stack", "version": "0"},
    },
}


@pytest.fixture
def app(upstream, tmp_path, monkeypatch):
    config = tmp_path / "winremote.toml"
    config.write_text("", encoding="utf-8")
    for name in (policy.ALLOWED_HOSTS_ENV, policy.ALLOWED_ORIGINS_ENV):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(policy.AUTH_KEY_ENV, KEY)
    upstream.calls.clear()
    upstream.W.cli.main(args=["--config", str(config), "--enable-all"], standalone_mode=False)
    middleware = upstream.calls[-1]["middleware"]
    assert [m.cls for m in middleware] == [HostOriginGuard, upstream.auth.AuthKeyMiddleware]
    return upstream.W.mcp.http_app(middleware=middleware)


def send_all(app, requests):
    """Run the app's lifespan and send (method, path, headers) requests in order."""

    async def go():
        statuses = []
        async with app.router.lifespan_context(app):
            transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 50000))
            async with httpx.AsyncClient(
                transport=transport, base_url="http://127.0.0.1:8090"
            ) as client:
                for method, path, headers in requests:
                    content = json.dumps(INITIALIZE) if method == "POST" else None
                    response = await client.request(method, path, headers=headers, content=content)
                    statuses.append(response.status_code)
        return statuses

    return asyncio.run(go())


def mcp_post(host, key=None, origin=None):
    headers = {
        "Host": host,
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }
    if key is not None:
        headers["Authorization"] = f"Bearer {key}"
    if origin is not None:
        headers["Origin"] = origin
    return ("POST", "/mcp", headers)


def test_host_origin_and_key_checks_over_the_asgi_stack(app):
    cases = [
        (mcp_post("attacker.example:8090", KEY), 421),
        (mcp_post("localhost.:8090", KEY), 421),
        (mcp_post("127.0.0.1:8090", KEY, origin="http://evil.example"), 403),
        (mcp_post("127.0.0.1:8090", KEY, origin="null"), 403),
        (mcp_post("127.0.0.1:8090"), 401),
        (mcp_post("127.0.0.1:8090", "x" * 40), 401),
        (mcp_post("127.0.0.1:8090", KEY), 200),
        (mcp_post("[::1]:8090", KEY), 200),
        (mcp_post("LOCALHOST:8090", KEY), 200),
        (mcp_post("203.0.113.9:8090", KEY), 200),
        (("GET", "/health", {"Host": "127.0.0.1:8090"}), 200),
        (("GET", "/health", {"Host": "attacker.example:8090"}), 421),
    ]
    statuses = send_all(app, [request for request, _ in cases])
    assert statuses == [expected for _, expected in cases]
