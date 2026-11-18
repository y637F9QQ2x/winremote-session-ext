from winremote_session_ext import policy
from winremote_session_ext.policy import HttpFacts, evaluate_http

KEY = "k" * 40


def facts(**overrides):
    base = dict(
        host="127.0.0.1",
        api_key=KEY,
        has_oauth=False,
        has_ip_allowlist=False,
        tls=False,
    )
    base.update(overrides)
    return HttpFacts(**base)


def test_argv_refuses_key_on_command_line_in_both_forms():
    assert policy.check_argv(["--auth-key", "x"])
    assert policy.check_argv(["--auth-key=x"])


def test_argv_refuses_insecure_reload_and_oauth():
    for option in (
        "--allow-insecure-remote",
        "--reload",
        "--oauth-client-id=a",
        "--oauth-client-secret=b",
    ):
        assert policy.check_argv([option]), option


def test_argv_refuses_install_subcommands():
    assert policy.check_argv(["install"])
    assert policy.check_argv(["--port", "8090", "uninstall"])


def test_argv_option_values_are_not_mistaken_for_subcommands():
    assert policy.check_argv(["--tools", "install"]) == []
    assert policy.check_argv(["--host", "127.0.0.1", "--port", "8090", "--enable-tier3"]) == []


def test_argv_allows_health_and_help():
    assert policy.check_argv(["health"]) == []
    assert policy.check_argv(["--help"]) == []


def test_auth_key_rules():
    assert policy.check_auth_key(None)
    assert policy.check_auth_key("short")
    assert policy.check_auth_key("k" * 31)
    assert policy.check_auth_key("k" * 39 + " ")
    assert policy.check_auth_key("k" * 39 + chr(0xE9))
    assert policy.check_auth_key(KEY) is None


def test_auth_key_with_a_final_line_break_is_refused():
    # A key file read without trimming ends in a line break; no client sends that.
    assert policy.check_auth_key(KEY + "\n")
    assert policy.check_auth_key(KEY + "\r\n")


def test_only_the_reviewed_upstream_version_is_supported():
    assert policy.upstream_version_supported("0.4.24")
    for other in ("0.4.23", "0.4.25", "0.4.24.post1", "0.4.24rc1", "0.5.0", ""):
        assert not policy.upstream_version_supported(other), other


def test_host_header_parsing():
    assert policy.split_host_header("LocalHost:8090") == "localhost"
    assert policy.split_host_header("[::1]:8090") == "::1"
    assert policy.split_host_header("::1") == "::1"
    assert policy.split_host_header("192.0.2.10") == "192.0.2.10"


def test_host_allowed_accepts_ip_literals_and_listed_names_only():
    names = policy.DEFAULT_HOST_NAMES | {"test-guest"}
    assert policy.host_allowed("127.0.0.1:8090", names)
    assert policy.host_allowed("localhost:18090", names)
    assert policy.host_allowed("[::1]:8090", names)
    assert policy.host_allowed("192.0.2.10:8090", names)
    assert policy.host_allowed("test-guest:8090", names)
    assert not policy.host_allowed("attacker.example:8090", names)
    assert not policy.host_allowed("localhost.:8090", names)
    assert not policy.host_allowed("2130706433:8090", names)
    assert not policy.host_allowed("", names)
    assert not policy.host_allowed(None, names)


def test_ip_literals_are_accepted_without_being_listed():
    assert policy.DEFAULT_HOST_NAMES == frozenset({"localhost"})
    assert policy.host_allowed("127.0.0.1", frozenset())
    assert policy.host_allowed("[::1]:8090", frozenset())


def test_origin_rules():
    assert policy.origin_allowed(None, frozenset())
    assert not policy.origin_allowed("http://attacker.example", frozenset())
    assert not policy.origin_allowed("null", frozenset())
    allowed = frozenset({"http://127.0.0.1:6274"})
    assert policy.origin_allowed("HTTP://127.0.0.1:6274/", allowed)


def test_http_facts_repr_does_not_show_the_key():
    assert KEY not in repr(facts())


def test_loopback_with_env_key_is_accepted():
    decision = evaluate_http(facts(), {policy.AUTH_KEY_ENV: KEY})
    assert decision.errors == []
    assert decision.allowed_host_names == policy.DEFAULT_HOST_NAMES
    assert decision.allowed_origins == frozenset()


def test_loopback_without_key_is_refused():
    decision = evaluate_http(facts(api_key=None), {})
    assert decision.errors


def test_key_that_differs_from_the_env_key_is_refused():
    # Defense in depth only: upstream 0.4.24 never resolves such a key, see
    # test_upstream.py for the real config file cases.
    decision = evaluate_http(facts(api_key="c" * 40), {policy.AUTH_KEY_ENV: KEY})
    assert any(policy.AUTH_KEY_ENV in e for e in decision.errors)


def test_weak_env_key_is_refused():
    decision = evaluate_http(facts(api_key="short"), {policy.AUTH_KEY_ENV: "short"})
    assert decision.errors


def test_oauth_is_refused():
    decision = evaluate_http(facts(has_oauth=True), {policy.AUTH_KEY_ENV: KEY})
    assert any("OAuth" in e for e in decision.errors)


def test_remote_bind_needs_allowlist_and_tls():
    decision = evaluate_http(facts(host="0.0.0.0"), {policy.AUTH_KEY_ENV: KEY})
    assert len(decision.errors) == 2


def test_remote_bind_with_allowlist_and_tls_is_accepted():
    decision = evaluate_http(
        facts(host="0.0.0.0", has_ip_allowlist=True, tls=True), {policy.AUTH_KEY_ENV: KEY}
    )
    assert decision.errors == [] and decision.warnings == []


def test_plain_http_remote_needs_explicit_opt_in_and_warns():
    env = {policy.AUTH_KEY_ENV: KEY, policy.ALLOW_PLAIN_HTTP_ENV: "1"}
    decision = evaluate_http(facts(host="192.0.2.10", has_ip_allowlist=True), env)
    assert decision.errors == []
    assert decision.warnings
    env[policy.ALLOW_PLAIN_HTTP_ENV] = "yes"
    assert evaluate_http(facts(host="192.0.2.10", has_ip_allowlist=True), env).errors


def test_extra_hosts_and_origins_from_env():
    env = {
        policy.AUTH_KEY_ENV: KEY,
        policy.ALLOWED_HOSTS_ENV: "Test-Guest:8090, other",
        policy.ALLOWED_ORIGINS_ENV: "http://127.0.0.1:6274/",
    }
    decision = evaluate_http(facts(), env)
    assert {"test-guest", "other"} <= decision.allowed_host_names
    assert decision.allowed_origins == frozenset({"http://127.0.0.1:6274"})
