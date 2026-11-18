# Candidate pull requests to winremote-mcp

This extension exists because upstream has no plugin interface and a few
behaviors needed changing. Each item below would remove code from this
repository if upstream accepted it. The heading of each item gives its size.
References are to winremote-mcp 0.4.24 as installed from PyPI.

## 1. Constant-time API key comparison (small, no behavior change)

- **Where:** `winremote/auth.py`, `AuthKeyMiddleware.dispatch`, which compares
  `auth_header == f"Bearer {self.auth_key}"`.
- **Change:** compare with `hmac.compare_digest` on bytes. Comparing `str`
  with `compare_digest` raises `TypeError` for non-ASCII input, and header
  values can contain any byte, so encode both sides first. This repository's
  `constant_time_equals()` does that.
- **Test:** the right key passes; a wrong key, a missing header and a header
  with the bytes `\xff\xfe` give 401
  (`tests/test_upstream.py::test_auth_patch_accepts_right_key_and_rejects_others`).
  The last case matters for the new code only: `compare_digest` on `str`
  would raise `TypeError` there, where `==` returns `False`.

## 2. Session reconnect: exit code, wrong session, read-only callers (small to medium)

- **Where:** `winremote/__main__.py`, `_ensure_session_connected`, used by the
  `ReconnectSession` tool and by the retry in `Snapshot` and
  `AnnotatedSnapshot`.
- **Problem 1, measured:** on one Windows 11 Pro machine (build 26300),
  `query session` printed a valid table and exited with code 1 (`qwinsta`
  exited with 0). The function returns "Failed to query sessions" for any
  non-zero exit, so on that machine it failed every time it ran.
- **Problem 2, from reading the code:** the loop keeps the last row that has a
  user name (or the console row). With more than one user session it can pick
  a session that is not the server's own and run `tscon` on it.
- **Problem 3, from reading the code:** `Snapshot` and `AnnotatedSnapshot`
  carry `readOnlyHint=True`, but after a failed screen grab they call the
  function, which can run `tscon` and move the session to the console.
- **Change:** take the server's own session id from `ProcessIdToSessionId`,
  read its state with `WTSQuerySessionInformationW(WTSConnectState)`, and run
  `tscon <own id> /dest:console` only when it is disconnected (or forced).
  Run `tscon` by its full path in System32. This removes the text parsing and
  the dependence on the display language (the current code lists Chinese state
  names by hand). For problem 3, either let only `ReconnectSession` attach,
  or drop `readOnlyHint` from the two tools. `attach_to_console()`,
  `make_session_reconnect()` and `winapi.py` in this repository are a working
  version.
- **Compatibility:** same return contract (`None` or an error string).

## 3. Version string (trivial)

The 0.4.24 wheel's `winremote/__init__.py` sets `__version__ = "0.4.23"`, so
`/health`, the `health` subcommand and the start banner report 0.4.23.
Reading the version from package metadata (`importlib.metadata.version`) would
keep them in step.

## 4. An extension entry point (medium, removes most of this repository)

- **Change:** in `cli()`, before `_apply_tool_filter`, load entry points from a
  group such as `winremote.extensions` and call each with the `FastMCP`
  instance and a small public registration function, for example
  `register_tool(name, tier)`, that updates `TOOL_TIERS`, `ALL_TOOLS` and the
  name lookup.
- **Effect here:** the launcher, the version and file hash checks and most of
  `compatibility_problems()` would no longer be needed. This repository would
  depend on one public function instead of the internal names listed in
  README.md, section "Limitations".

## 5. Warn about `--auth-key` on the command line (trivial)

Print a warning that the command line is visible to other processes and is
recorded by process-creation logging, and point to `WINREMOTE_AUTH_KEY`.
This repository refuses the option instead; a warning is the version suitable
for upstream, because refusing would break existing setups.

## 6. Read-only session tools (medium, optional)

`WhoAmI` and `SessionList` are generic, read-only and small (493 and 434 bytes
of tool definition, measured with `scripts/measure_tool_list.py`). They would
fit upstream's tier 1. `WaitForWindow` (754 bytes) overlaps with `Snapshot`
polling but costs one call instead of many.

## 7. Optional root for file reads (medium, optional)

`ReadResultFile` shows a pattern upstream could offer for `FileRead`: an
optional `--file-root` that confines reads, checked on the path as written
(before anything opens it, so a UNC path never reaches the network), on the
resolved path and on the final path of the opened handle, with files that
have more than one hard link refused.

## Not proposed upstream

These are choices for this extension's own threat model and would break
existing upstream users:

- requiring an API key on every HTTP bind, loopback included;
- refusing a non-loopback bind without TLS and an IP allowlist;
- refusing OAuth mode (only because it was not reviewed here);
- refusing `--allow-insecure-remote`, `--reload`, `install` and `uninstall`;
- refusing a `winremote.toml` that sets `server.auth_key`.
