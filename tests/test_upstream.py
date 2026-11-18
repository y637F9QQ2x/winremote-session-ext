"""The extension inside a real winremote-mcp import. No server is started:
the `upstream` fixture replaces mcp.run with a recorder, and tool calls go
through fastmcp's in-memory client (no socket)."""

import asyncio
import json
import os
import re
import uuid
from pathlib import Path

import pytest

from winremote_session_ext import launcher, policy, tools
from winremote_session_ext.guard import HostOriginGuard

# click comes with winremote-mcp; without upstream the whole module is skipped.
click = pytest.importorskip("click")

KEY = "k" * 40


def test_tools_are_registered_in_tier_1(upstream):
    tiers = upstream.tiers
    registered = set(upstream.W._get_registered_tools())
    assert set(tools.TOOL_NAMES) <= registered
    assert registered - set(tools.TOOL_NAMES) == upstream.upstream_tools
    assert set(tools.TOOL_NAMES) <= tiers.TOOL_TIERS["tier1"]
    assert not set(tools.TOOL_NAMES) & (tiers.TOOL_TIERS["tier2"] | tiers.TOOL_TIERS["tier3"])
    assert tiers.normalize_tool_names(["whoami", "readresultfile"]) == [
        "WhoAmI",
        "ReadResultFile",
    ]
    assert set(tools.TOOL_NAMES) <= tiers.resolve_enabled_tools(disable_tier2=True)


def test_install_is_idempotent(upstream):
    before = set(upstream.W._get_registered_tools())
    W, tiers, auth, security = upstream.W, upstream.tiers, upstream.auth, upstream.security
    assert upstream.extension.install(W, tiers, auth, security) == upstream.names
    assert set(W._get_registered_tools()) == before


def test_upstream_was_imported_without_dotenv(upstream):
    # `from dotenv import load_dotenv` binds the name right before upstream calls it.
    assert upstream.W.load_dotenv is launcher._no_dotenv


def test_upstream_reconnect_is_replaced(upstream):
    assert getattr(upstream.W._ensure_session_connected, "winremote_session_ext", False)


def test_upstream_call_sites_match_the_replacement(upstream):
    # The replacement tells ReconnectSession (force=...) from the Snapshot and
    # AnnotatedSnapshot retries (no argument). The file hash check pins this source.
    source = Path(upstream.W.__file__).read_text(encoding="utf-8")
    calls = re.findall(r"_ensure_session_connected\(([^)]*)\)", source)
    assert sorted(calls) == ["", "", "force: bool = False", "force=force"]


def _call(upstream, coro_factory):
    from fastmcp import Client

    async def go():
        async with Client(upstream.W.mcp) as client:
            return await coro_factory(client)

    return asyncio.run(go())


def _text(result):
    return json.loads(result.content[0].text)


@pytest.mark.parametrize("arguments,force", [({}, False), ({"force": True}, True)])
def test_reconnect_session_runs_the_extension_attach(upstream, monkeypatch, arguments, force):
    seen = []

    def fake_attach(force=False):
        seen.append(force)
        return "tscon"

    monkeypatch.setattr(tools, "attach_to_console", fake_attach)
    result = _call(upstream, lambda c: c.call_tool("ReconnectSession", arguments))
    assert "Session connected to console" in result.content[0].text
    assert seen == [force]


def _request(path, authorization=None):
    from starlette.requests import Request

    headers = [(b"host", b"127.0.0.1:8090")]
    if authorization is not None:
        headers.append((b"authorization", authorization))
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": path,
            "query_string": b"",
            "scheme": "http",
            "server": ("127.0.0.1", 8090),
            "headers": headers,
        }
    )


def _dispatch(upstream, request, auth_key=KEY):
    middleware = upstream.auth.AuthKeyMiddleware(app=None, auth_key=auth_key)

    async def call_next(_request):
        return "passed"

    return asyncio.run(middleware.dispatch(request, call_next))


def test_auth_patch_accepts_right_key_and_rejects_others(upstream):
    assert _dispatch(upstream, _request("/mcp", f"Bearer {KEY}".encode())) == "passed"
    assert _dispatch(upstream, _request("/mcp", b"Bearer wrong")).status_code == 401
    assert _dispatch(upstream, _request("/mcp")).status_code == 401
    # Non-ASCII header bytes: hmac.compare_digest on str would raise TypeError here.
    assert _dispatch(upstream, _request("/mcp", b"Bearer \xff\xfe")).status_code == 401
    assert _dispatch(upstream, _request("/health")) == "passed"


def test_auth_patch_never_matches_an_empty_key(upstream):
    assert _dispatch(upstream, _request("/mcp", b"Bearer "), auth_key="").status_code == 401


def test_tool_definitions(upstream):
    listed = _call(upstream, lambda c: c.list_tools())
    # The wire form (camelCase), as a client receives it.
    wire = {t.name: t.model_dump(mode="json", by_alias=True, exclude_none=True) for t in listed}
    for name in tools.TOOL_NAMES:
        assert wire[name]["annotations"]["readOnlyHint"] is True
    assert wire["WaitForWindow"]["inputSchema"]["required"] == ["title"]


def test_readme_lists_the_measured_definition_sizes(upstream):
    # The same measurement as scripts/measure_tool_list.py.
    listed = _call(upstream, lambda c: c.list_tools())
    sizes = {
        t.name: len(
            json.dumps(
                t.model_dump(mode="json", by_alias=True, exclude_none=True), separators=(",", ":")
            ).encode("utf-8")
        )
        for t in listed
    }
    readme = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8")
    rows = re.findall(r"^\| `(\w+)` \| 1 \| .* \| ([\d,]+) bytes \|$", readme, re.MULTILINE)
    assert {name: int(n.replace(",", "")) for name, n in rows} == {
        name: sizes[name] for name in tools.TOOL_NAMES
    }
    total = sum(sizes[name] for name in tools.TOOL_NAMES)
    assert f"| the four extension tools | 4 | {total:,} |" in readme


def test_whoami_and_sessionlist_in_memory(upstream):
    who = _text(_call(upstream, lambda c: c.call_tool("WhoAmI", {})))
    assert who["sid"].startswith("S-1-") and "interactive" in who
    listing = _text(_call(upstream, lambda c: c.call_tool("SessionList", {})))
    assert listing["own_session_id"] in {s["session_id"] for s in listing["sessions"]}


def test_wait_for_window_times_out_cleanly(upstream):
    args = {"title": "no-such-window-" + uuid.uuid4().hex, "timeout_s": 0}
    report = _text(_call(upstream, lambda c: c.call_tool("WaitForWindow", args)))
    assert report["found"] is False and report["polls"] == 1


def test_read_result_file_in_memory(upstream, tmp_path, monkeypatch):
    (tmp_path / "result.txt").write_text("ok", encoding="utf-8")
    monkeypatch.setenv(policy.RESULT_DIR_ENV, str(tmp_path))
    report = _text(_call(upstream, lambda c: c.call_tool("ReadResultFile", {"path": "result.txt"})))
    assert report["content"] == "ok"


# ---------------------------------------------------------------- upstream's CLI


@pytest.fixture
def cli_env(upstream, tmp_path, monkeypatch):
    """Run upstream's real click CLI with an empty config file and a clean env."""
    empty = tmp_path / "winremote.toml"
    empty.write_text("", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("NO_COLOR", "1")
    for name in (
        policy.AUTH_KEY_ENV,
        policy.ALLOW_PLAIN_HTTP_ENV,
        policy.ALLOWED_HOSTS_ENV,
        policy.ALLOWED_ORIGINS_ENV,
        "WINREMOTE_OAUTH_CLIENT_ID",
        "WINREMOTE_OAUTH_CLIENT_SECRET",
    ):
        monkeypatch.delenv(name, raising=False)
    upstream.calls.clear()

    def run_cli(*args, config=empty):
        # --enable-all keeps upstream's tool filter from removing tools other tests use.
        upstream.W.cli.main(
            args=["--config", str(config), "--enable-all", *args], standalone_mode=False
        )
        return upstream.calls[-1]

    run_cli.empty_config = empty
    return run_cli


def test_cli_loopback_with_env_key_gets_guard_first(cli_env, monkeypatch, upstream):
    monkeypatch.setenv(policy.AUTH_KEY_ENV, KEY)
    kwargs = cli_env()
    classes = [m.cls for m in kwargs["middleware"]]
    assert classes == [HostOriginGuard, upstream.auth.AuthKeyMiddleware]
    # Removed before serving, so child processes of the server do not inherit it.
    assert policy.AUTH_KEY_ENV not in os.environ


def test_cli_without_key_is_refused(cli_env, upstream):
    with pytest.raises(click.ClickException):
        cli_env()
    assert upstream.calls == []


def test_cli_config_file_key_is_refused_with_and_without_the_variable(
    cli_env, monkeypatch, upstream, tmp_path
):
    keyed = tmp_path / "keyed.toml"
    keyed.write_text('[server]\nauth_key = "' + "c" * 40 + '"\n', encoding="utf-8")
    monkeypatch.setenv(policy.AUTH_KEY_ENV, KEY)
    with pytest.raises(click.ClickException) as info:
        cli_env(config=keyed)
    assert "server.auth_key" in info.value.message
    monkeypatch.delenv(policy.AUTH_KEY_ENV)
    with pytest.raises(click.ClickException) as info:
        cli_env(config=keyed)
    assert "server.auth_key" in info.value.message
    assert upstream.calls == []


def test_cli_remote_bind_without_tls_and_allowlist_is_refused(cli_env, monkeypatch, upstream):
    monkeypatch.setenv(policy.AUTH_KEY_ENV, KEY)
    with pytest.raises(click.ClickException) as info:
        cli_env("--host", "0.0.0.0")
    assert "ip-allowlist" in info.value.message and "TLS" in info.value.message
    assert upstream.calls == []


def test_cli_remote_bind_with_tls_and_allowlist(cli_env, monkeypatch, upstream):
    monkeypatch.setenv(policy.AUTH_KEY_ENV, KEY)
    kwargs = cli_env(
        "--host",
        "0.0.0.0",
        "--ip-allowlist",
        "192.0.2.1",
        "--ssl-certfile",
        "server.crt",
        "--ssl-keyfile",
        "server.key",
    )
    classes = [m.cls for m in kwargs["middleware"]]
    assert classes == [
        HostOriginGuard,
        upstream.security.IPAllowlistMiddleware,
        upstream.auth.AuthKeyMiddleware,
    ]
    uvicorn = kwargs.get("uvicorn_config") or kwargs.get("uvicorn_args")
    assert uvicorn["ssl_certfile"] == "server.crt" and uvicorn["ssl_keyfile"] == "server.key"


def test_cli_plain_http_host_only_opt_in(cli_env, monkeypatch):
    monkeypatch.setenv(policy.AUTH_KEY_ENV, KEY)
    monkeypatch.setenv(policy.ALLOW_PLAIN_HTTP_ENV, "1")
    kwargs = cli_env("--host", "192.0.2.10", "--ip-allowlist", "192.0.2.1")
    assert kwargs["host"] == "192.0.2.10"
    assert kwargs["middleware"][0].cls is HostOriginGuard


def test_cli_stdio_is_passed_through_and_drops_the_key(cli_env, monkeypatch):
    monkeypatch.setenv(policy.AUTH_KEY_ENV, KEY)
    kwargs = cli_env("--transport", "stdio")
    assert kwargs == {"transport": "stdio"}
    assert policy.AUTH_KEY_ENV not in os.environ


# ---------------------------------------------------------------- the launcher


def test_launcher_refuses_key_on_command_line(capsys):
    assert launcher.main(["--auth-key", "x"]) == 2
    assert "WINREMOTE_AUTH_KEY" in capsys.readouterr().err


def test_launcher_exit_codes(cli_env, monkeypatch, upstream, capsys):
    base = ["--config", str(cli_env.empty_config), "--enable-all"]
    assert launcher.main(base) == 1
    assert "refused to start" in capsys.readouterr().err
    assert launcher.main([*base, "--port", "not-a-number"]) == 2
    monkeypatch.setenv(policy.AUTH_KEY_ENV, KEY)
    assert launcher.main(base) == 0
    assert upstream.calls and upstream.calls[-1]["middleware"][0].cls is HostOriginGuard


def test_help_hides_the_refused_options_and_commands(upstream, capsys):
    assert launcher.main(["--help"]) == 0
    out = capsys.readouterr().out
    for upstream_help_text in (
        "API key for authentication",
        "Enable hot reload",
        "Allow non-loopback HTTP bind",
        "OAuth client ID",
        "OAuth client secret",
        "Create a Windows scheduled task",
        "Remove the WinRemoteMCP scheduled task",
    ):
        assert upstream_help_text not in out
    assert "--port" in out and "health" in out
    assert policy.AUTH_KEY_ENV in out
