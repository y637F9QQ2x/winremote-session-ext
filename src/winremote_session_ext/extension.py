"""Hook the extension into an imported winremote-mcp.

Upstream has no plugin interface, so this module works against named
internals of winremote-mcp 0.4.24. It checks the installed version, the
hashes of the upstream files it relies on and every internal name first, and
refuses to continue if anything differs (fail closed): a partial install
could start a server without the security changes.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import sys
from importlib import metadata
from pathlib import Path

from . import __version__, policy, tools
from .guard import HostOriginGuard

_MARKER = "_winremote_session_ext"

# SHA-256 of the upstream files whose code this module replaces, wraps or relies
# on, as shipped in winremote_mcp-0.4.24-py3-none-any.whl (the values match the
# RECORD file of that wheel).
UPSTREAM_FILES_SHA256 = {
    "__main__.py": "657dbbdddd26f9bf92ca9fd659992126bb355431582d45a794574e7a1e2010b1",
    "auth.py": "c8e450953e3ea6f43961e0736aca5a0e05f9d4083a75a2ad5801b6cca50aab46",
    "config.py": "20b1a8dab86dbcca3dce2d06539c8ea999c7fe3271c37376e45e495a00f9e1ae",
}


class CompatibilityError(RuntimeError):
    """The installed winremote-mcp is not the release this extension was checked against."""


def _log(message: str) -> None:
    # stderr only: with --transport stdio, stdout carries the MCP protocol.
    sys.stderr.write(f"[winremote-session-ext] {message}\n")
    sys.stderr.flush()


def source_problems(package_dir, expected: dict[str, str] = UPSTREAM_FILES_SHA256) -> list[str]:
    """Compare upstream files in package_dir with their expected SHA-256 values."""
    problems: list[str] = []
    for name, digest in expected.items():
        path = Path(package_dir) / name
        try:
            found = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError as exc:
            problems.append(f"cannot read winremote/{name}: {exc}")
            continue
        if found != digest:
            problems.append(
                f"winremote/{name} differs from the {policy.SUPPORTED_UPSTREAM} release "
                f"(SHA-256 {found})"
            )
    return problems


def compatibility_problems(
    W, tiers, auth_mod, security_mod, check_version: bool = True, check_sources: bool = True
):
    problems: list[str] = []
    if check_version:
        try:
            found = metadata.version("winremote-mcp")
        except metadata.PackageNotFoundError:
            found = None
        if found is None:
            problems.append("winremote-mcp distribution metadata not found")
        elif not policy.upstream_version_supported(found):
            problems.append(
                f"winremote-mcp {found} is installed; this extension supports only "
                f"{policy.SUPPORTED_UPSTREAM}"
            )
    if check_sources:
        main_file = getattr(W, "__file__", None)
        if not main_file:
            problems.append("winremote.__main__ has no source file")
        else:
            problems.extend(source_problems(Path(main_file).parent))
    for owner, label, names in (
        (
            W,
            "winremote.__main__",
            (
                "mcp",
                "cli",
                "ToolError",
                "ToolAnnotations",
                "load_config",
                "_ensure_session_connected",
                "_get_registered_tools",
            ),
        ),
        (tiers, "winremote.tiers", ("TOOL_TIERS", "ALL_TOOLS", "_NAME_LOOKUP")),
        (auth_mod, "winremote.auth", ("AuthKeyMiddleware", "OAuthOnlyMiddleware", "_PUBLIC_PATHS")),
        (security_mod, "winremote.security", ("IPAllowlistMiddleware",)),
    ):
        for name in names:
            if not hasattr(owner, name):
                problems.append(f"{label}.{name} is missing")
    if problems:
        return problems
    if not all(callable(getattr(W.mcp, a, None)) for a in ("tool", "run")):
        problems.append("winremote.__main__.mcp has no tool() or run()")
    tier_map = tiers.TOOL_TIERS
    if not (
        isinstance(tier_map, dict)
        and all(isinstance(tier_map.get(t), set) for t in ("tier1", "tier2", "tier3"))
    ):
        problems.append("winremote.tiers.TOOL_TIERS has an unexpected shape")
    if not isinstance(tiers.ALL_TOOLS, set) or not isinstance(tiers._NAME_LOOKUP, dict):
        problems.append("winremote.tiers.ALL_TOOLS or _NAME_LOOKUP has an unexpected type")
    if not callable(getattr(auth_mod.AuthKeyMiddleware, "dispatch", None)):
        problems.append("winremote.auth.AuthKeyMiddleware.dispatch is missing")
    if not problems:
        taken = set(tiers.ALL_TOOLS) | set(W._get_registered_tools())
        clash = sorted(taken.intersection(tools.TOOL_NAMES))
        if clash:
            problems.append("upstream already defines " + ", ".join(clash))
    return problems


# ---------------------------------------------------------------- auth


def constant_time_equals(supplied: str, expected: str) -> bool:
    """hmac.compare_digest on bytes: str input must be ASCII, header values may not be."""
    return hmac.compare_digest(
        supplied.encode("utf-8", "surrogatepass"), expected.encode("utf-8", "surrogatepass")
    )


def patch_auth(auth_mod) -> None:
    """Replace AuthKeyMiddleware.dispatch.

    The body follows winremote-mcp 0.4.24 auth.py (MIT, Copyright (c) 2025
    winremote contributors) with two changes: the bearer header is compared
    in constant time on bytes, and an empty configured key never matches
    (upstream adds the middleware only when a key is set, so the second change
    has no effect there). See THIRD_PARTY_NOTICES.md.
    """
    from starlette.responses import JSONResponse

    cls = auth_mod.AuthKeyMiddleware
    if getattr(cls, _MARKER, False):
        return

    async def dispatch(self, request, call_next):
        if request.url.path in auth_mod._PUBLIC_PATHS:
            return await call_next(request)
        header = request.headers.get("Authorization", "")
        if self.auth_key and constant_time_equals(header, f"Bearer {self.auth_key}"):
            return await call_next(request)
        if self.oauth_validator and header.startswith("Bearer "):
            if self.oauth_validator(header[7:]):
                return await call_next(request)
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    cls.dispatch = dispatch
    setattr(cls, _MARKER, True)


def refuse_config_key(W) -> None:
    """Wrap upstream's load_config so that a config file with server.auth_key stops the launch.

    Upstream's CLI uses the key from the file when WINREMOTE_AUTH_KEY is unset and
    ignores it when the variable is set. Either way the key stays in the file in
    plain text, so the file is refused instead.
    """
    original = W.load_config

    def load_config(path):
        cfg = original(path)
        if cfg.server.auth_key:
            import click

            raise click.ClickException(
                f"{path} sets server.auth_key. Remove it: winremote-session-ext takes "
                f"the API key only from {policy.AUTH_KEY_ENV}."
            )
        return cfg

    W.load_config = load_config


# ---------------------------------------------------------------- HTTP launch policy


def http_facts(run_kwargs: dict, auth_mod, security_mod) -> policy.HttpFacts:
    """Read what upstream resolved (CLI, env and config file) from mcp.run() kwargs."""
    middleware = list(run_kwargs.get("middleware") or [])

    def of(cls):
        return [m for m in middleware if getattr(m, "cls", None) is cls]

    api = of(auth_mod.AuthKeyMiddleware)
    api_key = api[0].kwargs.get("auth_key") if api else None
    has_oauth = bool(of(auth_mod.OAuthOnlyMiddleware)) or any(
        m.kwargs.get("oauth_validator") for m in api
    )
    uvicorn = run_kwargs.get("uvicorn_config") or run_kwargs.get("uvicorn_args") or {}
    return policy.HttpFacts(
        host=str(run_kwargs.get("host") or "127.0.0.1"),
        api_key=api_key,
        has_oauth=has_oauth,
        has_ip_allowlist=bool(of(security_mod.IPAllowlistMiddleware)),
        tls=bool(uvicorn.get("ssl_certfile") and uvicorn.get("ssl_keyfile")),
    )


def guarded_run_kwargs(run_kwargs: dict, auth_mod, security_mod, env) -> dict:
    """Apply the HTTP policy. Returns new kwargs with the Host/Origin guard first.

    Raises click.ClickException with every reason when the launch is refused.
    """
    import click
    from starlette.middleware import Middleware

    decision = policy.evaluate_http(http_facts(run_kwargs, auth_mod, security_mod), dict(env))
    if decision.errors:
        raise click.ClickException(
            "winremote-session-ext refused to start:\n  - " + "\n  - ".join(decision.errors)
        )
    for warning in decision.warnings:
        _log("WARNING: " + warning)
    guard = Middleware(
        HostOriginGuard,
        allowed_host_names=decision.allowed_host_names,
        allowed_origins=decision.allowed_origins,
    )
    out = dict(run_kwargs)
    out["middleware"] = [guard, *list(run_kwargs.get("middleware") or [])]
    return out


def wrap_run(mcp, auth_mod, security_mod, env=os.environ) -> None:
    original = mcp.run

    def run(*args, **kwargs):
        transport = kwargs.get("transport", args[0] if args else None)
        if transport == "stdio":
            _log("stdio transport: no network listener, the HTTP checks do not apply")
        else:
            kwargs = guarded_run_kwargs(kwargs, auth_mod, security_mod, env)
            _log("HTTP checks passed; Host/Origin guard and constant-time key check active")
        # For HTTP the middleware holds the key now, and stdio does not use it.
        # Removing it keeps programs started through Shell or App from inheriting it.
        env.pop(policy.AUTH_KEY_ENV, None)
        return original(*args, **kwargs)

    mcp.run = run


# ---------------------------------------------------------------- command line


def hide_refused_cli_parts(cli) -> None:
    """Hide the options and subcommands the launcher refuses from upstream's --help."""
    refused = set(policy.REFUSED_OPTIONS)
    for param in getattr(cli, "params", ()):
        if refused.intersection(getattr(param, "opts", ())):
            param.hidden = True
    commands = getattr(cli, "commands", {})
    for name in policy.REFUSED_SUBCOMMANDS:
        if name in commands:
            commands[name].hidden = True
    cli.help = "Start winremote-mcp with winremote-session-ext."
    cli.epilog = (
        f"Refused by winremote-session-ext: {', '.join(policy.REFUSED_OPTIONS)} and the "
        f"{' and '.join(policy.REFUSED_SUBCOMMANDS)} commands. The API key comes only "
        f"from the {policy.AUTH_KEY_ENV} environment variable."
    )


# ---------------------------------------------------------------- install


def install(
    W,
    tiers,
    auth_mod,
    security_mod,
    *,
    check_version: bool = True,
    check_sources: bool = True,
    env=os.environ,
) -> tuple[str, ...]:
    """Register the tools, classify them into tier 1 and apply the security changes.

    Call once, after importing winremote.__main__ and before its cli() runs.
    """
    if getattr(W.mcp, _MARKER, False):
        return tools.TOOL_NAMES
    problems = compatibility_problems(
        W, tiers, auth_mod, security_mod, check_version, check_sources
    )
    if problems:
        raise CompatibilityError("; ".join(problems))

    patch_auth(auth_mod)
    refuse_config_key(W)
    W._ensure_session_connected = tools.make_session_reconnect(W.ToolError)
    names = tools.register(W.mcp, W.ToolError, W.ToolAnnotations)

    # In-place updates: winremote.__main__ imported these very set objects.
    tiers.TOOL_TIERS["tier1"].update(names)
    tiers.ALL_TOOLS.update(names)
    tiers._NAME_LOOKUP.update({name.lower(): name for name in names})

    hide_refused_cli_parts(W.cli)
    wrap_run(W.mcp, auth_mod, security_mod, env)
    setattr(W.mcp, _MARKER, True)
    _log(f"{__version__} loaded: added {', '.join(names)}")
    return names
