"""Fail-closed checks of extension.install() against fake upstream modules."""

import hashlib
from types import SimpleNamespace

import pytest

from winremote_session_ext import extension, policy


def fake_upstream(**drop):
    class Auth:
        async def dispatch(self, request, call_next):
            return None

    mcp = SimpleNamespace(tool=lambda **kw: lambda f: f, run=lambda **kw: None)
    W = SimpleNamespace(
        mcp=mcp,
        cli=lambda: None,
        ToolError=RuntimeError,
        ToolAnnotations=dict,
        load_config=lambda path: SimpleNamespace(server=SimpleNamespace(auth_key=None)),
        _ensure_session_connected=lambda force=False: None,
        _get_registered_tools=lambda: {"Snapshot": object()},
    )
    tiers = SimpleNamespace(
        TOOL_TIERS={"tier1": {"Snapshot"}, "tier2": set(), "tier3": set()},
        ALL_TOOLS={"Snapshot"},
        _NAME_LOOKUP={"snapshot": "Snapshot"},
    )
    auth = SimpleNamespace(
        AuthKeyMiddleware=Auth, OAuthOnlyMiddleware=object, _PUBLIC_PATHS=frozenset()
    )
    security = SimpleNamespace(IPAllowlistMiddleware=object)
    for owner, name in drop.items():
        delattr({"W": W, "tiers": tiers, "auth": auth, "security": security}[owner], name)
    return W, tiers, auth, security


def problems_of(*modules, **kwargs):
    kwargs.setdefault("check_version", False)
    kwargs.setdefault("check_sources", False)
    return extension.compatibility_problems(*modules, **kwargs)


def test_complete_fake_has_no_problems():
    assert problems_of(*fake_upstream()) == []


@pytest.mark.parametrize(
    "owner,name",
    [
        ("W", "_ensure_session_connected"),
        ("W", "load_config"),
        ("tiers", "_NAME_LOOKUP"),
        ("auth", "_PUBLIC_PATHS"),
    ],
)
def test_missing_internal_is_reported(owner, name):
    problems = problems_of(*fake_upstream(**{owner: name}))
    assert any(name in p for p in problems)


def test_name_clash_is_reported():
    W, tiers, auth, security = fake_upstream()
    tiers.ALL_TOOLS.add("WhoAmI")
    assert any("WhoAmI" in p for p in problems_of(W, tiers, auth, security))


@pytest.mark.parametrize("version", ["0.4.23", "0.4.25", "0.5.0"])
def test_other_upstream_versions_are_reported(monkeypatch, version):
    monkeypatch.setattr(extension.metadata, "version", lambda name: version)
    problems = problems_of(*fake_upstream(), check_version=True)
    assert any(version in p for p in problems)


def test_fake_without_source_file_is_reported():
    problems = problems_of(*fake_upstream(), check_sources=True)
    assert any("source file" in p for p in problems)


def test_modified_upstream_files_are_reported(tmp_path):
    for name in extension.UPSTREAM_FILES_SHA256:
        (tmp_path / name).write_text("# not the reviewed file\n", encoding="utf-8")
    W, tiers, auth, security = fake_upstream()
    W.__file__ = str(tmp_path / "__main__.py")
    problems = problems_of(W, tiers, auth, security, check_sources=True)
    for name in extension.UPSTREAM_FILES_SHA256:
        assert any(f"winremote/{name} differs" in p for p in problems), name


def test_source_hashes_are_compared(tmp_path):
    (tmp_path / "a.py").write_bytes(b"reviewed\n")
    (tmp_path / "b.py").write_bytes(b"changed\n")
    expected = {
        "a.py": hashlib.sha256(b"reviewed\n").hexdigest(),
        "b.py": hashlib.sha256(b"reviewed\n").hexdigest(),
        "c.py": "0" * 64,
    }
    problems = extension.source_problems(tmp_path, expected)
    assert len(problems) == 2
    assert "winremote/b.py differs" in problems[0]
    assert "cannot read winremote/c.py" in problems[1]


def test_install_changes_nothing_when_incompatible():
    W, tiers, auth, security = fake_upstream(auth="_PUBLIC_PATHS")
    original_dispatch = auth.AuthKeyMiddleware.dispatch
    original_run = W.mcp.run
    original_load_config = W.load_config
    original_reconnect = W._ensure_session_connected
    with pytest.raises(extension.CompatibilityError):
        extension.install(W, tiers, auth, security, check_version=False, check_sources=False)
    assert auth.AuthKeyMiddleware.dispatch is original_dispatch
    assert W.mcp.run is original_run
    assert W.load_config is original_load_config
    assert W._ensure_session_connected is original_reconnect
    assert tiers.ALL_TOOLS == {"Snapshot"}


def test_config_file_with_a_key_is_refused():
    click = pytest.importorskip("click")
    W, *_ = fake_upstream()
    keyed = SimpleNamespace(server=SimpleNamespace(auth_key="c" * 40))
    W.load_config = lambda path: keyed
    extension.refuse_config_key(W)
    with pytest.raises(click.ClickException) as info:
        W.load_config("winremote.toml")
    assert "server.auth_key" in info.value.message
    assert "c" * 40 not in info.value.message


def test_config_file_without_a_key_is_passed_through():
    W, *_ = fake_upstream()
    plain = SimpleNamespace(server=SimpleNamespace(auth_key=None))
    W.load_config = lambda path: plain
    extension.refuse_config_key(W)
    assert W.load_config("winremote.toml") is plain


def test_constant_time_equals_handles_non_ascii():
    assert extension.constant_time_equals("Bearer abc", "Bearer abc")
    assert not extension.constant_time_equals("Bearer " + chr(0xFF), "Bearer abc")


def test_refused_cli_parts_are_hidden():
    def option(*opts):
        return SimpleNamespace(opts=list(opts), hidden=False)

    params = [option("--auth-key"), option("--reload"), option("--port"), option("--tools")]
    commands = {name: SimpleNamespace(hidden=False) for name in ("install", "uninstall", "health")}
    cli = SimpleNamespace(params=params, commands=commands, help="", epilog="")
    extension.hide_refused_cli_parts(cli)
    assert [p.hidden for p in params] == [True, True, False, False]
    assert {n: c.hidden for n, c in commands.items()} == {
        "install": True,
        "uninstall": True,
        "health": False,
    }
    assert policy.AUTH_KEY_ENV in cli.epilog
