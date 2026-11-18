# winremote-session-ext

An extension for [winremote-mcp](https://github.com/dddabtc/winremote-mcp),
the MCP (Model Context Protocol) server that controls a Windows desktop. It
adds four read-only tools that report the state of the Windows logon session
the server runs in. It also changes how upstream attaches a disconnected
session to the console, and it restricts how the server's HTTP endpoint can be
exposed.

It is an independent repository, not a GitHub fork. winremote-mcp is installed
from PyPI and must be present; this repository contains no upstream files. It
is not affiliated with or endorsed by the winremote-mcp authors.

## Contents

- [Why it exists](#why-it-exists)
- [Tools](#tools)
- [What it changes compared with upstream](#what-it-changes-compared-with-upstream)
- [Requirements](#requirements)
- [Install](#install)
- [Usage](#usage)
- [Configuration](#configuration)
- [Security and trust model](#security-and-trust-model)
- [Limitations](#limitations)
- [Tests](#tests)
- [Upstream contributions](#upstream-contributions)
- [Related projects](#related-projects)
- [Credits and license](#credits-and-license)

## Why it exists

winremote-mcp's desktop tools (`Snapshot`, `Click`, `Type`, ...) act on the
desktop of the logon session that the server process runs in. A check that
depends on a real desktop (a dialog must appear, an action must run as a
given user or at a given integrity level) needs answers that upstream does
not report:

- Which account, which integrity level and which session is the server in?
- Can that session show windows at all (session 0 and service window stations
  cannot)?
- Did the expected window appear?
- Is the session still attached after the RDP client disconnected?

## Tools

| Tool | Upstream tier | Returns | Definition size |
|---|---|---|---|
| `WhoAmI` | 1 | user, SID, integrity level, elevation, Administrators group state, session id and state, console session id, window station, desktop, `interactive` | 493 bytes |
| `SessionList` | 1 | every session from `WTSEnumerateSessionsW`: id, station, state, user, domain | 434 bytes |
| `WaitForWindow` | 1 | visible top-level windows whose title matches (title, pid, hwnd), or `found: false` after `timeout_s` (at most 120) | 754 bytes |
| `ReadResultFile` | 1 | text of a file inside `WINREMOTE_EXT_RESULT_DIR` (at most 1 MiB), size, `truncated`, SHA-256 of a complete read | 725 bytes |

All four are marked read-only (`readOnlyHint: true`) and join upstream's
tier 1, so upstream's `--tools` and `--exclude-tools` options apply to them
as to any upstream tool. Tier 1 and tier 2 are on by default upstream; tier 3
(`Shell`, `FileWrite`, ...) is off unless `--enable-tier3` or `--enable-all`
is given. Usage step 6 explains the definition size.

The tools read Windows state through documented Win32 calls (`ctypes`), not
by parsing command output, so states, ids and flags do not depend on the
display language. Names can depend on the language: `WhoAmI` returns account
and domain names as Windows reports them, and Windows localizes them for
built-in accounts (`NT AUTHORITY\SYSTEM` in English). Window titles, which
`WaitForWindow` matches, are localized too. None of the tools starts a
process. The only process the extension starts is `tscon.exe`, through the
attach code that replaces upstream's (item 7 below).

Example `WhoAmI` result for a standard user in an RDP session (values are
illustrative, not from a real machine):

```json
{"user":"EXAMPLE-PC\\tester","sid":"S-1-5-21-1111111111-2222222222-3333333333-1001",
 "integrity_level":"medium","integrity_rid":"0x2000","elevated":false,
 "elevation_type":"default","administrators_group":"absent","pid":4242,
 "session_id":2,"session_state":"active","active_console_session_id":1,
 "on_console":false,"window_station":"WinSta0","window_station_visible":true,
 "desktop":"Default","interactive":true}
```

`administrators_group` is `deny-only` for an administrator running with the
filtered (non-elevated) UAC token and `enabled` when elevated.

## What it changes compared with upstream

The extension starts upstream's own command line after the steps below. Every
upstream option works, except the refused ones listed here.

1. **An API key is required for HTTP, also on loopback.** Every process on
   the machine, including processes of other users, can connect to a
   loopback port. The server does not start on any HTTP bind without a key.
2. **The key comes only from the `WINREMOTE_AUTH_KEY` environment variable.**
   `--auth-key` is refused. Task Manager shows process command lines, and
   process-creation logging records them (Windows event 4688 when
   command-line auditing is on, Sysmon event 1). None of these shows
   environment variables. A `winremote.toml` that sets `server.auth_key` is
   refused too, whether or not the variable is set. The key must be at least
   32 printable ASCII characters, with no spaces or line breaks.
3. **Host and Origin validation.** A request whose Host header is a name not
   in the allowlist gets 421. A request that carries an Origin header not in
   the allowlist gets 403. WebSocket requests get the same checks. IP
   literals are accepted as Host, because DNS rebinding needs a host name.
   The two clients checked here, fastmcp's `Client` and
   `scripts/Invoke-WinRemoteTool.ps1`, send no Origin header (read from their
   source). The guard is a plain ASGI middleware in this repository
   (`guard.py`), so it does not depend on the fastmcp version or settings.
4. **Constant-time key comparison.** Upstream compares the bearer header with
   `==`. The extension replaces `AuthKeyMiddleware.dispatch` with a version
   that differs in two ways: it compares with `hmac.compare_digest` on bytes,
   and an empty configured key never matches. The practical timing risk of
   `==` is low; the change is small. Upstream adds the middleware only when a
   key is set, so the second difference has no effect there.
5. **A non-loopback bind needs `--ip-allowlist` and TLS.** Without
   `--ssl-certfile` and `--ssl-keyfile` the server refuses to start, unless
   `WINREMOTE_EXT_ALLOW_PLAIN_HTTP=1` is set for an isolated host-only network
   (it then prints a warning).
6. **Refused options:** `--allow-insecure-remote`, `--reload` (the reloaded
   worker would run without the extension), `--oauth-client-id` and
   `--oauth-client-secret` (upstream's OAuth mode was not reviewed for this
   extension), and the `install` and `uninstall` subcommands (they manage a
   scheduled task that starts upstream without the extension). `--help` does
   not list them.
7. **Console attach uses the WTS API, touches only the server's own session,
   and does not run from read-only tools.** Upstream's `ReconnectSession`
   tool, and the retry in `Snapshot` and `AnnotatedSnapshot` after a failed
   screen grab, call an internal function, `_ensure_session_connected`. It
   parses `query session` output and treats a non-zero exit code as failure.
   On the machine used for testing, `query session` printed a valid session
   table and exited with code 1, while `qwinsta` exited with 0. The function
   also uses the last table row that has a user name (or the console row),
   which is not necessarily the server's own session. The extension replaces
   it. `ReconnectSession` then runs `tscon` by its full path for the server's
   own session, when that session is disconnected or `force` is true.
   `Snapshot` and `AnnotatedSnapshot` are marked read-only, so they no longer
   attach the session themselves: for a disconnected session they return an
   error that names `ReconnectSession`, unless `WINREMOTE_EXT_AUTO_ATTACH=1`
   is set. When `query session` works and the session is not disconnected,
   upstream retries the failed grab once; with the extension the two tools
   return the first grab's error instead, also unless
   `WINREMOTE_EXT_AUTO_ATTACH=1` is set.
8. **No `.env` files.** Upstream calls python-dotenv's `load_dotenv()` when it
   is imported, and python-dotenv then looks for a `.env` file in the folder
   of the upstream package and in every folder above it. Before the launcher
   imports upstream, it replaces that function with one that does nothing,
   so the key and the `WINREMOTE_EXT_*` settings come only from the real
   environment. fastmcp still reads its own settings (variables that start
   with `FASTMCP_`) from a `.env` file in the working directory.
9. **Fail closed.** The server does not start unless the installed
   winremote-mcp is exactly 0.4.24, its `__main__.py`, `auth.py` and
   `config.py` match the SHA-256 values of the 0.4.24 wheel, and every
   upstream internal the extension uses is present. Another release, a
   modified upstream file or a partial install could otherwise run without
   the changes above.

## Requirements

- Windows. Checked on one machine only: Windows 11 Pro 26H2 (build
  26300.9818).
- Python 3.11 or later: fastmcp 4.2.1 and starlette 1.10.0, the versions the
  tests ran with, require it. The install with `constraints.txt` needs 3.11.5
  or later, because soupsieve 4.1.1 does. The tests ran on Python 3.14.6 only.
- winremote-mcp 0.4.24 exactly; the extension refuses any other release.
  `constraints.txt` lists the version of every other package the tests ran
  with, among them fastmcp 4.2.1, mcp 2.3.0 and starlette 1.10.0.
- Windows PowerShell 5.1 or PowerShell 7 for `scripts/Start-SessionServer.ps1`;
  PowerShell 7 for `scripts/Invoke-WinRemoteTool.ps1`.

## Install

On the Windows machine, as the account that will run the server:

```powershell
git clone https://github.com/y637F9QQ2x/winremote-session-ext
cd winremote-session-ext
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt -c constraints.txt
.\.venv\Scripts\python.exe -m pip install . -c constraints.txt
```

`py` is the Python launcher that the python.org installer can add. Without
it, run `python -m venv .venv` with the python.exe you want to use.

Keep the virtual environment in a folder that only this account and
administrators can write to. Anyone who can change its files can change the
server's code.

The virtual environment also contains upstream's own `winremote-mcp`
command. It starts upstream without the extension, so none of the changes
above apply. Start the server only with `winremote-session-ext`,
`python -m winremote_session_ext` or `scripts/Start-SessionServer.ps1`.

## Usage

### 1. Create a key file that only you can read

```powershell
$dir = Join-Path $env:USERPROFILE '.winremote'
New-Item -ItemType Directory -Force $dir | Out-Null
$me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
icacls $dir /inheritance:r /grant:r "*${me}:(OI)(CI)F" | Out-Null
.\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(32), end='')" |
    Set-Content -NoNewline (Join-Path $dir 'key.txt')
```

The ACL is set before the key is written, so the file never exists with
inherited permissions. `secrets.token_urlsafe(32)` gives 43 characters.

### 2. Start the server inside the session

Log on as the account (console or RDP), then in that session:

```powershell
$results = Join-Path $env:USERPROFILE 'winremote-results'
New-Item -ItemType Directory -Force $results | Out-Null
.\scripts\Start-SessionServer.ps1 -Python .\.venv\Scripts\python.exe `
    -KeyFile "$env:USERPROFILE\.winremote\key.txt" -ResultDir $results
```

`-ResultDir` must be an existing folder. A folder in the user profile gets
the profile's permissions, which by default allow only the account, SYSTEM
and Administrators.

The script refuses to run in session 0, warns if the key file is readable by
Everyone, Authenticated Users or BUILTIN\Users, and passes the key to the
server through its environment only. Afterwards it restores the calling
session's variables (with `-Background`, right after the start).
`-Background` starts the server hidden, with logs in
`%LOCALAPPDATA%\winremote-session-ext`. Without the script:

```powershell
try {
    $env:WINREMOTE_AUTH_KEY = (Get-Content -Raw "$env:USERPROFILE\.winremote\key.txt").Trim()
    .\.venv\Scripts\python.exe -m winremote_session_ext --host 127.0.0.1 --port 8090
}
finally { Remove-Item Env:WINREMOTE_AUTH_KEY -ErrorAction SilentlyContinue }
```

The `finally` block removes the key from the shell again, so programs
started from it later do not inherit it.

`winremote-session-ext` (installed by pip) is the same entry point. Exit
codes: 0 is a normal end, 1 a refused configuration (the message lists every
reason), 2 a refused option or a usage error, 3 means winremote-mcp is
missing or not the supported release.

Windows PowerShell's default execution policy on client editions
(`Restricted`) does not run scripts. Run them from PowerShell 7 (default
`RemoteSigned`), or start Windows PowerShell with
`-ExecutionPolicy RemoteSigned` for that process.

### 3. Connect a client

From the client machine, open the tunnel:

```bash
ssh -N -L 8090:127.0.0.1:8090 <user>@<windows-host>
```

For an MCP client that runs local MCP servers over stdio (for example Claude
Desktop's local server configuration), use the
[mcp-remote](https://www.npmjs.com/package/mcp-remote) bridge with a header
file, so the key is neither in the client's JSON configuration nor on a
command line. The header file holds one line, `Authorization: Bearer <key>`,
and should be readable only by you. See
[`examples/claude_desktop_config.example.json`](examples/claude_desktop_config.example.json):

```json
{
  "mcpServers": {
    "winremote-session-ext": {
      "command": "cmd",
      "args": ["/c", "npx", "-y", "mcp-remote@0.16.6", "http://127.0.0.1:8090/mcp",
               "--header-file", "C:\\Users\\<you>\\.winremote\\headers.txt"]
    }
  }
}
```

`cmd /c` is there because `npx` on Windows is a batch file (`npx.cmd`), which
Node does not start without a shell; on macOS or Linux use `"command": "npx"`
and drop `"/c"`. `--header-file` is documented in the mcp-remote README at
version 0.16.6; pin a version you have reviewed. This client setup is not
exercised by the tests in this repository.

### 4. Call one tool from a script

```powershell
$keyFile = "$env:USERPROFILE\.winremote\key.txt"
.\scripts\Invoke-WinRemoteTool.ps1 -KeyFile $keyFile -Tool WhoAmI
.\scripts\Invoke-WinRemoteTool.ps1 -KeyFile $keyFile -Tool WaitForWindow -ArgsJson '{"title":"Notepad","timeout_s":30}'
```

`-KeyFile` reads the key into a variable of the script; it is not put in the
environment. Without `-KeyFile`, the script uses `WINREMOTE_AUTH_KEY`. Exit
code 0 is success, 1 means the tool returned an error, 2 is a transport or
protocol failure. `-TimeoutSec` (default 150) limits the `tools/call`
request, which is longer than the 120 s that `WaitForWindow` waits at most.
The script refuses a plain `http://` URL to a non-loopback host unless
`-AllowPlainHttp` is given.

### 5. Keep the session usable after RDP disconnects

When the RDP client disconnects, the session becomes `disconnected` and its
desktop is not drawn, so screenshots and input stop working; `WhoAmI` then
reports `"session_state":"disconnected"`. The server keeps running. Call
upstream's `ReconnectSession` to attach the session to the console (item 7
above). It runs `tscon <own session id> /dest:console` when the session is
disconnected, and with `force: true` also when it is not. Read "Console
attach" in the [trust model](#security-and-trust-model) first: the desktop is
then shown, unlocked, on the physical or VM console. `Snapshot` and
`AnnotatedSnapshot` return an error that names `ReconnectSession` instead of
attaching on their own, unless `WINREMOTE_EXT_AUTO_ATTACH=1` is set on the
server.

Whether `tscon` succeeds from a non-elevated server was not tested, for any
account type. The unit tests cover the decisions around it, with `tscon` and
the Windows calls replaced by fakes. On failure, `ReconnectSession` returns
`tscon`'s message.

### 6. Expose only the tools a task needs

Every enabled tool's definition is sent to the MCP client and takes space in
the model's context. A definition size is the length in bytes of the tool's
compact JSON definition as sent in `tools/list`. The numbers below come from
`python scripts/measure_tool_list.py --tools <the set below>`, which lists
the tools through fastmcp 4.2.1's in-memory client (no server) with
winremote-mcp 0.4.24:

| Tool set | Tools | Bytes |
|---|---|---|
| the four extension tools | 4 | 2,406 |
| upstream alone, enabled by default (tiers 1 and 2) | 30 | 18,931 |
| upstream with the extension, enabled by default | 34 | 21,337 |
| upstream alone, every registered tool (all tiers) | 45 | 28,326 |
| the `--tools` set below | 10 | 6,518 |

With upstream's default tiers, the extension adds 2,406 bytes, 13 percent of
upstream's 18,931. Token counts depend on the client's tokenizer and are not
given here.

A small set for a UI check, using upstream's `--tools` option:

```powershell
.\scripts\Start-SessionServer.ps1 -Python .\.venv\Scripts\python.exe `
    -KeyFile "$env:USERPROFILE\.winremote\key.txt" -ServerArgs '--tools',
    'WhoAmI,SessionList,WaitForWindow,ReadResultFile,ReconnectSession,Snapshot,Click,Type,Shortcut,FocusWindow'
```

## Configuration

| Variable | Meaning |
|---|---|
| `WINREMOTE_AUTH_KEY` | API key (upstream's variable). Required for HTTP. At least 32 printable ASCII characters, no spaces. Removed from the server's environment once the server starts. |
| `WINREMOTE_EXT_RESULT_DIR` | The only directory `ReadResultFile` reads from. Unset: the tool returns an error. |
| `WINREMOTE_EXT_ALLOWED_HOSTS` | Comma-separated host names accepted in the Host header, in addition to `localhost` and any IP literal. |
| `WINREMOTE_EXT_ALLOWED_ORIGINS` | Comma-separated origins accepted in the Origin header, for example a browser-based MCP inspector. Unset: every request with an Origin header is refused. |
| `WINREMOTE_EXT_ALLOW_PLAIN_HTTP` | `1` permits plain HTTP on a non-loopback bind (host-only networks). Any other value is ignored. |
| `WINREMOTE_EXT_AUTO_ATTACH` | `1` makes `Snapshot` and `AnnotatedSnapshot` handle a failed screen grab as upstream's own code does: run `tscon` if the session is disconnected, then try the grab once more. Any other value is ignored. |

These variables come from the server's environment only: the extension does
not load `.env` files (item 8 above). With `--transport stdio` there is no
network listener, and the HTTP rules above do not apply. A `winremote.toml`
that sets `server.auth_key` is still refused, and `WINREMOTE_AUTH_KEY` is
still removed from the server's environment.

## Security and trust model

**What the server is.** It is remote control of a Windows desktop. Whoever
holds the API key can use every enabled tool as the server's Windows account.
With the default tiers 1 and 2, that already means running any command as
that account: the key holder can type into any window, including the Run
dialog or a terminal. Tier 3 (`Shell`, `App`, ...) makes it direct. Treat the
key like that account's password.

**Trusted:** the key holder, processes that run as the same Windows account,
and the administrators of the machine. The last two can read the key file
and the server's memory. Once the launch checks pass, the extension removes
`WINREMOTE_AUTH_KEY` from the server's environment, so programs started
through `Shell` or `App` do not inherit it. **Not trusted:** other local
users (they can reach a loopback port, but need the key), web pages in a
local browser (blocked by the key and by the Host/Origin check), and anything
on the network beyond the transport chosen below.

**Transport, in order of preference:**

1. **Loopback plus an SSH tunnel.** The server listens on `127.0.0.1`; the
   client connects through `ssh -N -L 8090:127.0.0.1:8090 <user>@<windows-host>`
   (OpenSSH Server on Windows). Nothing listens on the network except SSH.
2. **TLS** with upstream's `--ssl-certfile` and `--ssl-keyfile`, plus
   `--ip-allowlist` with the client addresses. A client that connects by host
   name, for example the name in the certificate, needs that name in
   `WINREMOTE_EXT_ALLOWED_HOSTS`; otherwise every request gets 421.
3. **Plain HTTP on an isolated host-only virtual network**, only with
   `WINREMOTE_EXT_ALLOW_PLAIN_HTTP=1` and `--ip-allowlist`. The bearer key is
   sent in clear text with every request. Anything that can read traffic on
   that network (another VM on the same virtual switch, the host, a packet
   capture) can copy the key and replay it. There is no replay protection.
   Use this only for disposable test machines.

**Account and privileges.** Run the server as the account whose desktop you
need, at that account's normal integrity level, in that account's logon
session. The extension never elevates. It creates no services, scheduled
tasks, firewall rules or logon settings. A service or a session-0 process has
no interactive desktop and is the wrong place for this server; `WhoAmI`
reports `interactive: false` there.

**Network exposure on Windows.** A non-loopback bind also needs an inbound
firewall rule, which an administrator creates and scopes to the port and the
client address, for example:

```powershell
$client = '192.0.2.10'  # the client's address
New-NetFirewallRule -DisplayName 'winremote-session-ext' -Direction Inbound `
    -Protocol TCP -LocalPort 8090 -RemoteAddress $client -Profile Private -Action Allow
```

**Console attach.** `ReconnectSession` runs
`tscon <own session id> /dest:console`, and so do `Snapshot` and
`AnnotatedSnapshot` when `WINREMOTE_EXT_AUTO_ATTACH=1` is set. When it
succeeds, the session's desktop is shown on the physical or VM console
without a lock screen, and anyone with access to that console can use the
session. The session that had the console before is disconnected.

**ReadResultFile.** It reads only regular files inside
`WINREMOTE_EXT_RESULT_DIR`. A requested path that lies outside the directory
as written is refused before anything opens it: an absolute path elsewhere, a
UNC path such as `\\host\share\x`, a device path such as `\\.\pipe\x`, a path
on another drive, or `..` that leaves the directory. So the path in a request
cannot make the server open a named pipe or a network share (opening a share
authenticates to that host as the server's account). A path inside is
resolved with links and junctions followed, the final path of the opened
handle is checked again (`GetFinalPathNameByHandleW`), and a file with more
than one hard link is refused. So neither a junction swapped in after the
path was resolved nor a hard link to a file elsewhere leads outside the
directory. This keeps the tool, and a client or model that calls it, inside
that directory. It is not a boundary against the key holder, who can read
other files in other ways, for example by typing commands through the tier 2
tools. Do not point the variable at a directory that holds secrets.

**Not covered:** a malicious local administrator; a compromised MCP client;
misuse of the tools by the key holder; upstream's `/health` endpoint, which
stays unauthenticated, is exempt from `--ip-allowlist` (upstream's allowlist
middleware skips that path) and returns the status and the upstream version
string.

Vulnerability reports: see [SECURITY.md](SECURITY.md).

## Limitations

- Windows only, checked on one Windows 11 machine. Windows 10 and Windows
  Server were not tested. Python versions other than 3.14.6 were not tested.
- No test starts the HTTP server or sends a request over a network. The
  middleware stack that upstream's real command line builds is tested in
  memory through httpx2's ASGI transport, and the tools are called through
  fastmcp's in-memory client. `Start-SessionServer.ps1` runs against a stub
  server process, and `Invoke-WinRemoteTool.ps1` against a replaced
  `Invoke-WebRequest`.
- `tscon` from a non-elevated server: not tested (see usage step 5).
- Upstream has no plugin interface, so the extension depends on named upstream
  internals: `winremote.__main__` (`mcp`, `cli`, `ToolError`,
  `ToolAnnotations`, `load_config`, `_ensure_session_connected`,
  `_get_registered_tools`), `winremote.tiers` (`TOOL_TIERS`, `ALL_TOOLS`,
  `_NAME_LOOKUP`), `winremote.auth` (`AuthKeyMiddleware`,
  `OAuthOnlyMiddleware`, `_PUBLIC_PATHS`) and `winremote.security`
  (`IPAllowlistMiddleware`). Because any other upstream release is refused,
  each upstream update needs a review and a new release of this extension.
- `WaitForWindow` sees visible top-level windows on the server's own desktop
  only. It cannot see the secure desktop (UAC consent prompt, the
  Ctrl+Alt+Del screen) or other sessions, and it matches titles only.
- `ReadResultFile` is for text. Binary content is decoded with replacement
  characters. The limit is 1 MiB per call. A file with more than one hard
  link is refused, also when every link lies inside the directory.
- The extension tools do not run through upstream's task manager: they are
  not listed by `GetRunningTasks`, and `CancelTask` cannot stop
  `WaitForWindow`. It ends at its timeout (120 s at most) plus the time of
  one window enumeration.

## Tests

```powershell
.\.venv\Scripts\python.exe -m pip install pytest -c constraints.txt
.\.venv\Scripts\python.exe -m pytest
```

What the tests do:

- pure-function tests of the policy, the guard and the helpers;
- the console attach decisions and the `WaitForWindow` deadline, with
  `tscon`, the Windows calls and the clock replaced by fakes;
- read-only Win32 calls on the test process itself;
- `ReadResultFile` against files in pytest temporary directories, including
  a junction and a hard link that point outside, and UNC, pipe and
  other-drive paths that must be refused before they are resolved (there
  `os.path.realpath` is replaced by a function that raises for any path but
  the directory, so these cases cannot reach the network);
- the extension installed into a real winremote-mcp import, with `mcp.run`
  replaced before installation so no server can start;
- upstream's real command line, including the TLS, stdio and config file
  cases, and the resulting middleware stack driven in memory through httpx2's
  ASGI transport;
- `tests/ps/check_scripts.ps1`, which parses every script with the
  PowerShell AST and tests the helper functions (it changes the ACL of one
  temporary file it creates);
- `tests/ps/check_script_runs.ps1`, which runs the scripts' main bodies:
  `Start-SessionServer.ps1` with a stub Python package in place of the
  server (in session 0 it checks that the script refuses instead), and
  `Invoke-WinRemoteTool.ps1` (PowerShell 7) with `Invoke-WebRequest`
  replaced by a function that answers like a server.

`tests/conftest.py` stops the run when the package was imported from
anywhere other than `src/`, so the tests always check this tree.

Result on the machine above, with Python 3.14.6 and the versions in
`constraints.txt`: 130 passed, with pytest started from PowerShell 7.7.0 and
from Windows PowerShell 5.1. In a virtual environment with only pytest
installed: 104 passed and 3 skipped (they need packages that come with
winremote-mcp). ruff 0.17.5 (`ruff check`, `ruff format --check`) reports no
findings with the configuration in `pyproject.toml`, and PSScriptAnalyzer
1.25.0 reports no findings for `scripts/` and `tests/ps/`.

The two pip commands under [Install](#install), with pytest and ruff added
as in the workflow, also ran in a new virtual environment, with pip taking
every package from PyPI. The installed `winremote-session-ext` command then
printed its help, refused `--auth-key`, `--reload` and `install` with exit
code 2, and ran `health`. The GitHub Actions workflow in
`.github/workflows/ci.yml` has not run yet.

## Upstream contributions

[UPSTREAM-PR.md](UPSTREAM-PR.md) lists the parts that would make sense as pull
requests to winremote-mcp, so this extension can shrink over time.

## Related projects

Other repositories by the same author:

- [binja-agent-mcp](https://github.com/y637F9QQ2x/binja-agent-mcp): an MCP
  server for Binary Ninja, built for LLM agents.
- [windbg-hyperv-mcp](https://github.com/y637F9QQ2x/windbg-hyperv-mcp): an MCP
  server for Windows kernel and user-mode debugging of one Hyper-V guest.
- [hyperv-lpe-lab](https://github.com/y637F9QQ2x/hyperv-lpe-lab): PowerShell
  scripts for a headless Hyper-V lab, with VM control that needs no elevation
  and guest commands over SSH as an administrator or as a standard user.
- [win-agent-probes](https://github.com/y637F9QQ2x/win-agent-probes):
  PowerShell probes for Windows security research; each prints one JSON
  document.

The author's blog: [y637f9qq2x.com](https://y637f9qq2x.com).

## Credits and license

Written by Kazuma Matsumoto ([y637F9QQ2x](https://github.com/y637F9QQ2x)).
Third-party projects:

- [winremote-mcp](https://github.com/dddabtc/winremote-mcp) by dddabtc and the
  winremote contributors, MIT License, Copyright (c) 2025 winremote
  contributors. Checked against version 0.4.24. `patch_auth()` in
  `extension.py` reimplements upstream's `AuthKeyMiddleware.dispatch` with
  two changes (a constant-time comparison on bytes, and no match for an empty
  configured key); [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) carries
  the upstream license and the wheel's SHA-256.
- [fastmcp](https://github.com/PrefectHQ/fastmcp) (Apache-2.0), used by upstream
  and by the tests.
- [mcp-remote](https://www.npmjs.com/package/mcp-remote) (MIT), used only in
  the client example.

License: MIT, Copyright (c) 2026 Kazuma Matsumoto. See [LICENSE](LICENSE).
