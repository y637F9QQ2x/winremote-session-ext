"""The four session tools, and the console attach code that replaces upstream's
_ensure_session_connected."""

from __future__ import annotations

import codecs
import hashlib
import json
import os
import stat
import struct
import subprocess
import time

from . import core, policy, winapi

# All four only read state, so they join upstream's tier 1.
TOOL_NAMES = ("WhoAmI", "SessionList", "WaitForWindow", "ReadResultFile")

MAX_WAIT_S = 120.0
MAX_READ_BYTES = 1_048_576
TSCON_TIMEOUT_S = 15
# After tscon exits with 0, the session state is read up to ATTACH_POLLS times,
# ATTACH_POLL_S apart, until it is active.
ATTACH_POLLS = 10
ATTACH_POLL_S = 0.2
_CREATE_NO_WINDOW = 0x08000000


def _dumps(value) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"))


# ---------------------------------------------------------------- identity


def whoami() -> dict:
    session_id = winapi.own_session_id()
    console = winapi.active_console_session_id()
    state = winapi.session_state(session_id)
    station, visible = winapi.window_station()
    report = winapi.token_summary()
    report.update(
        {
            "pid": os.getpid(),
            "session_id": session_id,
            "session_state": core.wts_state_name(state) if state is not None else None,
            "active_console_session_id": console,
            "on_console": console is not None and console == session_id,
            "window_station": station,
            "window_station_visible": visible,
            "desktop": winapi.thread_desktop(),
            "interactive": core.is_interactive(session_id, station, visible),
        }
    )
    return report


def sessions() -> dict:
    return {
        "own_session_id": winapi.own_session_id(),
        "active_console_session_id": winapi.active_console_session_id(),
        "sessions": winapi.list_sessions(),
    }


# ---------------------------------------------------------------- console attach


def tscon_path() -> str:
    """Full path of tscon.exe in the real System32 directory.

    A 32-bit Python on 64-bit Windows sees System32 redirected to SysWOW64;
    Sysnative is the name that reaches the real System32 from there.
    """
    if struct.calcsize("P") == 4:
        sysnative = os.path.join(winapi.windows_directory(), "Sysnative")
        if os.path.isdir(sysnative):
            return os.path.join(sysnative, "tscon.exe")
    return os.path.join(winapi.system_directory(), "tscon.exe")


def attach_to_console(force: bool = False) -> str:
    """Attach this process's own session to the console when it is disconnected.

    Returns "none" when nothing was needed and "tscon" when tscon ran and the
    session became active. Raises RuntimeError with the reason otherwise, and
    subprocess.TimeoutExpired when tscon does not exit in time. It never
    names another session.
    """
    own = winapi.own_session_id()
    if own == 0:
        raise RuntimeError("this process runs in session 0, which has no interactive desktop")
    if not core.needs_tscon(winapi.session_state(own), force):
        return "none"
    result = subprocess.run(
        [tscon_path(), str(own), "/dest:console"],
        capture_output=True,
        encoding="oem",
        errors="replace",
        timeout=TSCON_TIMEOUT_S,
        creationflags=_CREATE_NO_WINDOW,
    )
    if result.returncode != 0:
        message = (result.stderr or result.stdout or "").strip() or f"exit code {result.returncode}"
        raise RuntimeError("tscon failed: " + core.clip(message, 300))
    state = None
    for attempt in range(ATTACH_POLLS):
        if attempt:
            time.sleep(ATTACH_POLL_S)
        state = winapi.session_state(own)
        if state == core.WTS_ACTIVE:
            return "tscon"
    name = core.wts_state_name(state) if state is not None else "unknown"
    raise RuntimeError(f"tscon exited with code 0, but session {own} is {name}, not active")


def reconnect(force: bool) -> str | None:
    """attach_to_console() with upstream's return contract: None on success, else an error."""
    try:
        attach_to_console(force=force)
        return None
    except subprocess.TimeoutExpired:
        return "tscon timed out"
    except Exception as exc:
        return str(exc)


_NOT_GIVEN = object()


def make_session_reconnect(tool_error):
    """Build the replacement for upstream's _ensure_session_connected(force=False).

    In winremote-mcp 0.4.24 three tools call that function. ReconnectSession
    passes force=...: an explicit request, so tscon runs when it is needed.
    Snapshot and AnnotatedSnapshot call it with no argument after a failed
    screen grab. They are marked read-only, so that call does not run tscon
    unless WINREMOTE_EXT_AUTO_ATTACH=1. For a disconnected session it raises
    tool_error with a message that names ReconnectSession; otherwise it
    returns an error string, and the tool reports its own screen grab error.
    """

    def _ensure_session_connected(force=_NOT_GIVEN):
        if force is not _NOT_GIVEN:
            return reconnect(bool(force))
        if os.environ.get(policy.AUTO_ATTACH_ENV) == "1":
            return reconnect(False)
        try:
            own = winapi.own_session_id()
            state = winapi.session_state(own)
        except Exception as exc:
            return f"could not read the session state: {exc}"
        if state == core.WTS_DISCONNECTED:
            raise tool_error(
                f"session {own} is disconnected, so the screen cannot be captured. Call "
                "ReconnectSession to attach it to the console. Read-only tools do not do "
                f"that on their own unless {policy.AUTO_ATTACH_ENV}=1 is set on the server."
            )
        return "the session is not disconnected; no reconnect was attempted"

    _ensure_session_connected.winremote_session_ext = True
    return _ensure_session_connected


# ---------------------------------------------------------------- windows


def wait_for_window(needle: str, timeout: float, poll: float, exact: bool) -> dict:
    """Poll the visible top-level windows until one matches or the deadline passes.

    The last sleep is cut to the time that is left, so the call ends at the
    deadline plus the duration of one window enumeration.
    """
    started = time.monotonic()
    deadline = started + timeout
    polls = 0
    while True:
        polls += 1
        windows = winapi.visible_windows()
        hits = core.match_windows(windows, needle, exact=exact)
        now = time.monotonic()
        elapsed = round(now - started, 2)
        if hits:
            return {"found": True, "matches": hits[:20], "elapsed_s": elapsed, "polls": polls}
        if now >= deadline:
            return {
                "found": False,
                "elapsed_s": elapsed,
                "polls": polls,
                "visible_titles_sample": [core.clip(w["title"], 120) for w in windows[:20]],
            }
        time.sleep(min(poll, deadline - now))


# ---------------------------------------------------------------- result files


def read_result_file(requested: str, max_bytes: int, encoding: str, root: str | None) -> dict:
    if not root:
        raise ValueError(f"{policy.RESULT_DIR_ENV} is not set on the server")
    if not requested or "\x00" in requested:
        raise ValueError("path must be a non-empty string")
    codecs.lookup(encoding)
    limit = int(core.clamp(int(max_bytes), 1, MAX_READ_BYTES))

    root_real = os.path.realpath(root, strict=True)
    if not os.path.isdir(root_real):
        raise ValueError(f"{policy.RESULT_DIR_ENV} is not a directory")
    # A lexical check first, because realpath() opens the path it resolves. For
    # \\host\share\x that is an SMB connection with the server account's
    # credentials; \\.\pipe\x opens a named pipe.
    candidate = os.path.normpath(os.path.join(root_real, requested))
    if not core.is_within(candidate, root_real):
        raise PermissionError("path lies outside the result directory")
    real = os.path.realpath(candidate, strict=True)
    if not core.is_within(real, root_real):
        raise PermissionError("path resolves outside the result directory")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0)
    fd = os.open(real, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise PermissionError("path is not a regular file")
        # A hard link inside the root can name a file stored elsewhere, and both
        # path checks see only the name it was opened by.
        if info.st_nlink > 1:
            raise PermissionError("file has more than one hard link")
        # Check the opened handle too, so a swap after realpath() cannot escape the root.
        if not core.is_within(winapi.final_path_of_fd(fd), root_real):
            raise PermissionError("opened file lies outside the result directory")
        chunks = []
        remaining = limit + 1
        while remaining > 0:
            chunk = os.read(fd, min(remaining, 65536))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
    finally:
        os.close(fd)

    data = b"".join(chunks)
    truncated = len(data) > limit
    data = data[:limit]
    report = {
        "path": os.path.relpath(real, root_real),
        "size": info.st_size,
        "truncated": truncated,
        "content": data.decode(encoding, errors="replace"),
    }
    if not truncated:
        report["sha256"] = hashlib.sha256(data).hexdigest()
    return report


# ---------------------------------------------------------------- registration


def register(mcp, tool_error, annotations_cls) -> tuple[str, ...]:
    """Register the four tools on upstream's FastMCP instance."""

    def tool(title: str, **extra):
        annotations = annotations_cls(title=title, readOnlyHint=True, openWorldHint=False, **extra)
        # output_schema=None: results are JSON text; a wrapper schema would only add bytes
        # to every tools/list response.
        return mcp.tool(annotations=annotations, output_schema=None)

    @tool("WhoAmI", idempotentHint=True)
    def WhoAmI() -> str:
        """Identity of this server process: user, SID, integrity level, elevation, session id,
        window station and whether it can show windows on an interactive desktop. Use it to
        confirm which account and integrity level a UI action will run as."""
        try:
            return _dumps(whoami())
        except Exception as exc:
            raise tool_error(f"WhoAmI error: {exc}") from exc

    @tool("SessionList", idempotentHint=True)
    def SessionList() -> str:
        """Windows sessions from the WTS API: id, station, state (active, disconnected, ...),
        user and domain, plus this server's own session id and the console session id."""
        try:
            return _dumps(sessions())
        except Exception as exc:
            raise tool_error(f"SessionList error: {exc}") from exc

    @tool("WaitForWindow")
    def WaitForWindow(
        title: str, timeout_s: float = 15.0, poll_s: float = 0.5, exact: bool = False
    ) -> str:
        """Wait until a visible top-level window whose title contains `title` (case-insensitive;
        exact=true for a full match) appears on this session's desktop. Returns the matches
        (title, pid, hwnd) or found=false with a sample of visible titles. timeout_s max 120.
        The UAC secure desktop and other sessions are not visible to it."""
        needle = (title or "").strip()
        if not needle or len(needle) > 256:
            raise tool_error("title must be 1 to 256 characters")
        try:
            report = wait_for_window(
                needle,
                core.clamp(float(timeout_s), 0.0, MAX_WAIT_S),
                core.clamp(float(poll_s), 0.1, 5.0),
                bool(exact),
            )
            return _dumps(report)
        except Exception as exc:
            raise tool_error(f"WaitForWindow error: {exc}") from exc

    @tool("ReadResultFile", idempotentHint=True)
    def ReadResultFile(path: str, max_bytes: int = 65536, encoding: str = "utf-8") -> str:
        """Read a text file inside the server's result directory (WINREMOTE_EXT_RESULT_DIR),
        for example a marker a test program wrote. `path` is relative to that directory; paths
        that resolve outside it are refused. Returns content (max_bytes, max 1 MiB), size,
        truncated, and sha256 when the whole file was read."""
        try:
            report = read_result_file(
                path, max_bytes, encoding, os.environ.get(policy.RESULT_DIR_ENV)
            )
            return _dumps(report)
        except FileNotFoundError as exc:
            raise tool_error(f"ReadResultFile: not found: {path}") from exc
        except Exception as exc:
            raise tool_error(f"ReadResultFile error: {exc}") from exc

    return TOOL_NAMES
