import asyncio

import pytest

from winremote_session_ext.guard import HostOriginGuard
from winremote_session_ext.policy import DEFAULT_HOST_NAMES


def run(headers, origins=frozenset(), kind="http"):
    reached = []
    sent = []

    async def app(scope, receive, send):
        reached.append(True)

    async def send(message):
        sent.append(message)

    async def receive():
        return {"type": f"{kind}.request" if kind == "http" else "websocket.connect"}

    guard = HostOriginGuard(app, allowed_host_names=DEFAULT_HOST_NAMES, allowed_origins=origins)
    scope = {"type": kind, "headers": [(k.encode(), v.encode()) for k, v in headers]}
    asyncio.run(guard(scope, receive, send))
    return bool(reached), sent


def http_status(headers, origins=frozenset()):
    reached, sent = run(headers, origins)
    return reached, (sent[0]["status"] if sent else None)


def test_loopback_host_without_origin_passes():
    assert http_status([("host", "127.0.0.1:8090")]) == (True, None)


def test_rebinding_host_is_rejected_with_421():
    assert http_status([("host", "attacker.example:8090")]) == (False, 421)


def test_missing_host_is_rejected():
    assert http_status([]) == (False, 421)


def test_browser_origin_is_rejected_with_403():
    headers = [("host", "127.0.0.1:8090"), ("origin", "http://attacker.example")]
    assert http_status(headers) == (False, 403)


def test_listed_origin_passes():
    origins = frozenset({"http://127.0.0.1:6274"})
    headers = [("host", "localhost:8090"), ("origin", "http://127.0.0.1:6274")]
    assert http_status(headers, origins) == (True, None)


def test_websocket_gets_the_same_checks():
    reached, sent = run([("host", "attacker.example:8090")], kind="websocket")
    assert not reached and sent == [{"type": "websocket.close", "code": 1008}]
    headers = [("host", "127.0.0.1:8090"), ("origin", "http://attacker.example")]
    reached, sent = run(headers, kind="websocket")
    assert not reached and sent == [{"type": "websocket.close", "code": 1008}]
    reached, sent = run([("host", "127.0.0.1:8090")], kind="websocket")
    assert reached and sent == []


def test_lifespan_passes_through():
    reached = []

    async def app(scope, receive, send):
        reached.append(scope["type"])

    guard = HostOriginGuard(app, allowed_host_names=DEFAULT_HOST_NAMES, allowed_origins=frozenset())
    asyncio.run(guard({"type": "lifespan"}, None, None))
    assert reached == ["lifespan"]


def test_unknown_scope_type_is_refused():
    async def app(scope, receive, send):
        raise AssertionError("must not be reached")

    guard = HostOriginGuard(app, allowed_host_names=DEFAULT_HOST_NAMES, allowed_origins=frozenset())
    with pytest.raises(RuntimeError):
        asyncio.run(guard({"type": "something-else"}, None, None))
