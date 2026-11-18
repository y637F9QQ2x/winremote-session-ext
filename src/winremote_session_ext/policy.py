"""Launch and HTTP exposure policy.

Everything in this module is a pure function of its arguments, so the rules
can be unit tested without Windows, without upstream and without a server.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

AUTH_KEY_ENV = "WINREMOTE_AUTH_KEY"
ALLOWED_HOSTS_ENV = "WINREMOTE_EXT_ALLOWED_HOSTS"
ALLOWED_ORIGINS_ENV = "WINREMOTE_EXT_ALLOWED_ORIGINS"
ALLOW_PLAIN_HTTP_ENV = "WINREMOTE_EXT_ALLOW_PLAIN_HTTP"
RESULT_DIR_ENV = "WINREMOTE_EXT_RESULT_DIR"
AUTO_ATTACH_ENV = "WINREMOTE_EXT_AUTO_ATTACH"

MIN_KEY_LENGTH = 32
# Printable ASCII without the space. Used with fullmatch(): "$" in a re.match()
# pattern would also accept a key that ends in a newline.
_KEY_RE = re.compile(r"[\x21-\x7e]+")

# The only winremote-mcp release whose internals this extension was checked
# against. extension.compatibility_problems() also compares file hashes.
SUPPORTED_UPSTREAM = "0.4.24"

# Upstream CLI options this launcher refuses, with the reason shown to the user.
REFUSED_OPTIONS = {
    "--auth-key": (
        "pass the key in the WINREMOTE_AUTH_KEY environment variable; process-creation "
        "logging (event 4688 with command-line auditing, Sysmon event 1) records command "
        "lines, not environment variables"
    ),
    "--allow-insecure-remote": "this launcher never serves HTTP without authentication",
    "--reload": "a reloaded worker would start without this extension",
    "--oauth-client-id": "upstream OAuth mode has not been reviewed for this extension",
    "--oauth-client-secret": "upstream OAuth mode has not been reviewed for this extension",
}

# Upstream CLI options that consume the next token as their value.
VALUE_OPTIONS = frozenset(
    {
        "--transport",
        "--host",
        "--port",
        "--auth-key",
        "--config",
        "--tools",
        "--exclude-tools",
        "--ip-allowlist",
        "--ssl-certfile",
        "--ssl-keyfile",
        "--oauth-client-id",
        "--oauth-client-secret",
    }
)

REFUSED_SUBCOMMANDS = {
    "install": "it registers a scheduled task that starts upstream without this extension",
    "uninstall": "it removes the scheduled task created by upstream's install command",
}

# Host names accepted in the Host header without configuration. IP literals are
# accepted by host_allowed() itself, so they are not listed here.
DEFAULT_HOST_NAMES = frozenset({"localhost"})


def check_argv(argv: list[str]) -> list[str]:
    """Return one error string per refused option or subcommand in argv."""
    errors: list[str] = []
    skip_next = False
    for token in argv:
        if skip_next:
            skip_next = False
            continue
        if token.startswith("--"):
            name, has_value, _ = token.partition("=")
            if name in REFUSED_OPTIONS:
                errors.append(f"{name} is refused: {REFUSED_OPTIONS[name]}")
            if name in VALUE_OPTIONS and not has_value:
                skip_next = True
            continue
        if token in REFUSED_SUBCOMMANDS:
            errors.append(f"subcommand '{token}' is refused: {REFUSED_SUBCOMMANDS[token]}")
    return errors


def check_auth_key(key: str | None) -> str | None:
    """Return an error string if key is missing or weak, else None."""
    if not key:
        return f"{AUTH_KEY_ENV} is not set; HTTP transport requires an API key"
    if len(key) < MIN_KEY_LENGTH:
        return f"{AUTH_KEY_ENV} must be at least {MIN_KEY_LENGTH} characters"
    if not _KEY_RE.fullmatch(key):
        return f"{AUTH_KEY_ENV} must contain printable ASCII only, without spaces or line breaks"
    return None


def upstream_version_supported(text: str) -> bool:
    return text.strip() == SUPPORTED_UPSTREAM


def split_csv(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [part.strip() for part in raw.split(",") if part.strip()]


def is_loopback_host(host: str) -> bool:
    host = host.strip().strip("[]").lower()
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def split_host_header(value: str) -> str:
    """Return the lowercase host name or address from a Host header value."""
    value = value.strip().lower()
    if value.startswith("["):
        end = value.find("]")
        return value[1:end] if end > 0 else ""
    if value.count(":") == 1:
        return value.split(":", 1)[0]
    return value


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def host_allowed(host_header: str | None, allowed_names: frozenset[str]) -> bool:
    """Decide whether a Host header may reach the server.

    DNS rebinding needs a host name that an attacker controls, so an IP
    literal is accepted. A name is accepted only when it is listed.
    """
    if not host_header:
        return False
    host = split_host_header(host_header)
    if not host:
        return False
    return is_ip_literal(host) or host in allowed_names


def normalize_origin(origin: str) -> str:
    return origin.strip().rstrip("/").lower()


def origin_allowed(origin: str | None, allowed_origins: frozenset[str]) -> bool:
    """A request without Origin is allowed. With Origin it must be listed."""
    if origin is None:
        return True
    return normalize_origin(origin) in allowed_origins


@dataclass(frozen=True)
class HttpFacts:
    """What upstream resolved for one HTTP launch (from CLI, env and config)."""

    host: str
    # repr=False: a log line or traceback that prints the object must not print the key.
    api_key: str | None = field(repr=False)
    has_oauth: bool
    has_ip_allowlist: bool
    tls: bool


@dataclass
class HttpDecision:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    allowed_host_names: frozenset[str] = DEFAULT_HOST_NAMES
    allowed_origins: frozenset[str] = frozenset()


def evaluate_http(facts: HttpFacts, env: dict[str, str]) -> HttpDecision:
    """Apply the HTTP exposure rules to one resolved launch."""
    decision = HttpDecision()
    env_key = env.get(AUTH_KEY_ENV)

    if facts.has_oauth:
        decision.errors.append("upstream OAuth mode is refused by this extension")
    if not facts.api_key:
        decision.errors.append(f"HTTP transport requires an API key in {AUTH_KEY_ENV}")
    else:
        key_error = check_auth_key(env_key)
        if key_error:
            decision.errors.append(key_error)
        elif facts.api_key != env_key:
            # Not reachable with winremote-mcp 0.4.24: its CLI prefers the environment
            # variable over the config file, and extension.install() refuses a config
            # file that sets server.auth_key. Kept in case upstream changes either.
            decision.errors.append(f"the API key in use is not the one in {AUTH_KEY_ENV}")

    if not is_loopback_host(facts.host):
        if not facts.has_ip_allowlist:
            decision.errors.append(
                f"binding to {facts.host} requires --ip-allowlist with the client addresses"
            )
        if not facts.tls:
            if env.get(ALLOW_PLAIN_HTTP_ENV) == "1":
                decision.warnings.append(
                    f"serving plain HTTP on {facts.host}: the bearer key crosses the "
                    "network in clear text on every request"
                )
            else:
                decision.errors.append(
                    f"binding to {facts.host} without TLS is refused; use an SSH tunnel to "
                    f"127.0.0.1, set --ssl-certfile and --ssl-keyfile, or set "
                    f"{ALLOW_PLAIN_HTTP_ENV}=1 for an isolated host-only network"
                )

    extra_hosts = {split_host_header(h) for h in split_csv(env.get(ALLOWED_HOSTS_ENV))}
    decision.allowed_host_names = frozenset(DEFAULT_HOST_NAMES | {h for h in extra_hosts if h})
    decision.allowed_origins = frozenset(
        normalize_origin(o) for o in split_csv(env.get(ALLOWED_ORIGINS_ENV))
    )
    return decision
