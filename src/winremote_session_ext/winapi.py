"""Read-only Windows API calls through ctypes.

Nothing in this module changes system state. Importing it on another OS is
safe; calling a function there raises OSError.
"""

from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes

from . import core

_TOKEN_QUERY = 0x0008
_TOKEN_USER = 1
_TOKEN_GROUPS = 2
_TOKEN_ELEVATION_TYPE = 18
_TOKEN_ELEVATION = 20
_TOKEN_INTEGRITY_LEVEL = 25
_SIZE_ERRORS = (122, 24)  # ERROR_INSUFFICIENT_BUFFER, ERROR_BAD_LENGTH
_UOI_FLAGS = 1
_UOI_NAME = 2
_WSF_VISIBLE = 0x0001
_WTS_USER_NAME = 5
_WTS_DOMAIN_NAME = 7
_WTS_CONNECT_STATE = 8
_ADMINISTRATORS_SID = "S-1-5-32-544"

_dlls: dict[str, ctypes.WinDLL] = {}


def _dll(name: str):
    if sys.platform != "win32":
        raise OSError("this function needs Windows")
    if name not in _dlls:
        _dlls[name] = ctypes.WinDLL(name, use_last_error=True)
    return _dlls[name]


def _fail(what: str) -> OSError:
    code = ctypes.get_last_error()
    return OSError(code, f"{what} failed: {ctypes.FormatError(code).strip()}")


class _SidAndAttributes(ctypes.Structure):
    _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]


class _TokenGroups(ctypes.Structure):
    _fields_ = [("GroupCount", wintypes.DWORD), ("Groups", _SidAndAttributes * 1)]


class _UserObjectFlags(ctypes.Structure):
    _fields_ = [
        ("fInherit", wintypes.BOOL),
        ("fReserved", wintypes.BOOL),
        ("dwFlags", wintypes.DWORD),
    ]


class _WtsSessionInfo(ctypes.Structure):
    _fields_ = [
        ("SessionId", wintypes.DWORD),
        ("pWinStationName", wintypes.LPWSTR),
        ("State", ctypes.c_int),
    ]


_WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

_SIGNATURES = {
    ("kernel32", "GetCurrentProcess"): ([], wintypes.HANDLE),
    ("kernel32", "GetCurrentProcessId"): ([], wintypes.DWORD),
    ("kernel32", "GetCurrentThreadId"): ([], wintypes.DWORD),
    ("kernel32", "CloseHandle"): ([wintypes.HANDLE], wintypes.BOOL),
    ("kernel32", "LocalFree"): ([ctypes.c_void_p], ctypes.c_void_p),
    ("kernel32", "ProcessIdToSessionId"): (
        [wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)],
        wintypes.BOOL,
    ),
    ("kernel32", "WTSGetActiveConsoleSessionId"): ([], wintypes.DWORD),
    ("kernel32", "GetFinalPathNameByHandleW"): (
        [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD],
        wintypes.DWORD,
    ),
    ("kernel32", "GetSystemDirectoryW"): ([wintypes.LPWSTR, wintypes.UINT], wintypes.UINT),
    ("kernel32", "GetSystemWindowsDirectoryW"): (
        [wintypes.LPWSTR, wintypes.UINT],
        wintypes.UINT,
    ),
    ("advapi32", "OpenProcessToken"): (
        [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)],
        wintypes.BOOL,
    ),
    ("advapi32", "GetTokenInformation"): (
        [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ],
        wintypes.BOOL,
    ),
    ("advapi32", "ConvertSidToStringSidW"): (
        [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)],
        wintypes.BOOL,
    ),
    ("advapi32", "GetSidSubAuthorityCount"): ([ctypes.c_void_p], ctypes.POINTER(ctypes.c_ubyte)),
    ("advapi32", "GetSidSubAuthority"): (
        [ctypes.c_void_p, wintypes.DWORD],
        ctypes.POINTER(wintypes.DWORD),
    ),
    ("advapi32", "LookupAccountSidW"): (
        [
            wintypes.LPCWSTR,
            ctypes.c_void_p,
            wintypes.LPWSTR,
            ctypes.POINTER(wintypes.DWORD),
            wintypes.LPWSTR,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(ctypes.c_int),
        ],
        wintypes.BOOL,
    ),
    ("user32", "GetProcessWindowStation"): ([], wintypes.HANDLE),
    ("user32", "GetThreadDesktop"): ([wintypes.DWORD], wintypes.HANDLE),
    ("user32", "GetUserObjectInformationW"): (
        [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ],
        wintypes.BOOL,
    ),
    ("user32", "EnumWindows"): ([_WNDENUMPROC, wintypes.LPARAM], wintypes.BOOL),
    ("user32", "IsWindowVisible"): ([wintypes.HWND], wintypes.BOOL),
    ("user32", "GetWindowTextLengthW"): ([wintypes.HWND], ctypes.c_int),
    ("user32", "GetWindowTextW"): ([wintypes.HWND, wintypes.LPWSTR, ctypes.c_int], ctypes.c_int),
    ("user32", "GetWindowThreadProcessId"): (
        [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)],
        wintypes.DWORD,
    ),
    ("wtsapi32", "WTSEnumerateSessionsW"): (
        [
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(ctypes.POINTER(_WtsSessionInfo)),
            ctypes.POINTER(wintypes.DWORD),
        ],
        wintypes.BOOL,
    ),
    ("wtsapi32", "WTSQuerySessionInformationW"): (
        [
            wintypes.HANDLE,
            wintypes.DWORD,
            ctypes.c_int,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(wintypes.DWORD),
        ],
        wintypes.BOOL,
    ),
    ("wtsapi32", "WTSFreeMemory"): ([ctypes.c_void_p], None),
}


_typed: dict[tuple[str, str], object] = {}


def _fn(dll: str, name: str):
    key = (dll, name)
    if key not in _typed:
        func = getattr(_dll(dll), name)
        func.argtypes, func.restype = _SIGNATURES[key]
        _typed[key] = func
    return _typed[key]


# ---------------------------------------------------------------- token


def _token_info(token, info_class: int) -> ctypes.Array:
    get = _fn("advapi32", "GetTokenInformation")
    needed = wintypes.DWORD(0)
    get(token, info_class, None, 0, ctypes.byref(needed))
    if ctypes.get_last_error() not in _SIZE_ERRORS or needed.value == 0:
        raise _fail("GetTokenInformation(size)")
    buf = ctypes.create_string_buffer(needed.value)
    if not get(token, info_class, buf, needed, ctypes.byref(needed)):
        raise _fail("GetTokenInformation")
    return buf


def _token_dword(token, info_class: int) -> int:
    value = wintypes.DWORD(0)
    size = wintypes.DWORD(0)
    ok = _fn("advapi32", "GetTokenInformation")(
        token, info_class, ctypes.byref(value), ctypes.sizeof(value), ctypes.byref(size)
    )
    if not ok:
        raise _fail("GetTokenInformation")
    return int(value.value)


def _sid_string(psid) -> str:
    out = wintypes.LPWSTR()
    if not _fn("advapi32", "ConvertSidToStringSidW")(psid, ctypes.byref(out)):
        raise _fail("ConvertSidToStringSidW")
    try:
        return out.value or ""
    finally:
        _fn("kernel32", "LocalFree")(ctypes.cast(out, ctypes.c_void_p))


def _account_name(psid) -> str | None:
    name_len = wintypes.DWORD(256)
    domain_len = wintypes.DWORD(256)
    name = ctypes.create_unicode_buffer(name_len.value)
    domain = ctypes.create_unicode_buffer(domain_len.value)
    use = ctypes.c_int(0)
    ok = _fn("advapi32", "LookupAccountSidW")(
        None,
        psid,
        name,
        ctypes.byref(name_len),
        domain,
        ctypes.byref(domain_len),
        ctypes.byref(use),
    )
    if not ok:
        return None
    return f"{domain.value}\\{name.value}" if domain.value else name.value


def _integrity_rid(token) -> int:
    buf = _token_info(token, _TOKEN_INTEGRITY_LEVEL)
    label = _SidAndAttributes.from_buffer(buf)
    count = _fn("advapi32", "GetSidSubAuthorityCount")(label.Sid).contents.value
    return int(_fn("advapi32", "GetSidSubAuthority")(label.Sid, count - 1).contents.value)


def _administrators_attributes(token) -> int | None:
    buf = _token_info(token, _TOKEN_GROUPS)
    header = _TokenGroups.from_buffer(buf)
    array_type = _SidAndAttributes * header.GroupCount
    groups = array_type.from_buffer(buf, _TokenGroups.Groups.offset)
    for group in groups:
        if _sid_string(group.Sid) == _ADMINISTRATORS_SID:
            return int(group.Attributes)
    return None


def token_summary() -> dict:
    """Identity and elevation of the current process token."""
    token = wintypes.HANDLE()
    if not _fn("advapi32", "OpenProcessToken")(
        _fn("kernel32", "GetCurrentProcess")(), _TOKEN_QUERY, ctypes.byref(token)
    ):
        raise _fail("OpenProcessToken")
    try:
        user_buf = _token_info(token, _TOKEN_USER)
        user_sid = _SidAndAttributes.from_buffer(user_buf).Sid
        rid = _integrity_rid(token)
        return {
            "user": _account_name(user_sid),
            "sid": _sid_string(user_sid),
            "integrity_level": core.integrity_name(rid),
            "integrity_rid": f"0x{rid:04x}",
            "elevated": bool(_token_dword(token, _TOKEN_ELEVATION)),
            "elevation_type": core.elevation_type_name(_token_dword(token, _TOKEN_ELEVATION_TYPE)),
            "administrators_group": core.administrators_state(_administrators_attributes(token)),
        }
    finally:
        _fn("kernel32", "CloseHandle")(token)


# ---------------------------------------------------------------- session


def own_session_id() -> int:
    sid = wintypes.DWORD(0)
    pid = _fn("kernel32", "GetCurrentProcessId")()
    if not _fn("kernel32", "ProcessIdToSessionId")(pid, ctypes.byref(sid)):
        raise _fail("ProcessIdToSessionId")
    return int(sid.value)


def active_console_session_id() -> int | None:
    value = int(_fn("kernel32", "WTSGetActiveConsoleSessionId")())
    return None if value == core.NO_CONSOLE_SESSION else value


def _object_name(handle) -> str | None:
    get = _fn("user32", "GetUserObjectInformationW")
    needed = wintypes.DWORD(0)
    get(handle, _UOI_NAME, None, 0, ctypes.byref(needed))
    if needed.value == 0:
        return None
    buf = ctypes.create_unicode_buffer(needed.value // ctypes.sizeof(ctypes.c_wchar) + 1)
    if not get(handle, _UOI_NAME, buf, ctypes.sizeof(buf), ctypes.byref(needed)):
        return None
    return buf.value


def window_station() -> tuple[str | None, bool]:
    """Name of this process's window station and whether it is visible."""
    station = _fn("user32", "GetProcessWindowStation")()
    if not station:
        return None, False
    flags = _UserObjectFlags()
    needed = wintypes.DWORD(0)
    ok = _fn("user32", "GetUserObjectInformationW")(
        station, _UOI_FLAGS, ctypes.byref(flags), ctypes.sizeof(flags), ctypes.byref(needed)
    )
    visible = bool(ok and (flags.dwFlags & _WSF_VISIBLE))
    return _object_name(station), visible


def thread_desktop() -> str | None:
    desk = _fn("user32", "GetThreadDesktop")(_fn("kernel32", "GetCurrentThreadId")())
    return _object_name(desk) if desk else None


def _wts_query(session_id: int, info_class: int):
    buf = ctypes.c_void_p()
    size = wintypes.DWORD(0)
    ok = _fn("wtsapi32", "WTSQuerySessionInformationW")(
        None, session_id, info_class, ctypes.byref(buf), ctypes.byref(size)
    )
    if not ok:
        return None
    try:
        if info_class == _WTS_CONNECT_STATE:
            return ctypes.cast(buf, ctypes.POINTER(ctypes.c_int)).contents.value
        return ctypes.wstring_at(buf.value) if buf.value else ""
    finally:
        _fn("wtsapi32", "WTSFreeMemory")(buf)


def session_state(session_id: int) -> int | None:
    return _wts_query(session_id, _WTS_CONNECT_STATE)


def list_sessions() -> list[dict]:
    """All sessions on this machine from WTSEnumerateSessionsW."""
    info = ctypes.POINTER(_WtsSessionInfo)()
    count = wintypes.DWORD(0)
    if not _fn("wtsapi32", "WTSEnumerateSessionsW")(
        None, 0, 1, ctypes.byref(info), ctypes.byref(count)
    ):
        raise _fail("WTSEnumerateSessionsW")
    try:
        rows = []
        for i in range(count.value):
            entry = info[i]
            sid = int(entry.SessionId)
            rows.append(
                {
                    "session_id": sid,
                    "station": entry.pWinStationName or "",
                    "state": core.wts_state_name(int(entry.State)),
                    "user": _wts_query(sid, _WTS_USER_NAME) or None,
                    "domain": _wts_query(sid, _WTS_DOMAIN_NAME) or None,
                }
            )
        return rows
    finally:
        _fn("wtsapi32", "WTSFreeMemory")(info)


# ---------------------------------------------------------------- windows


def visible_windows() -> list[dict]:
    """Visible top-level windows with a title on this thread's desktop."""
    rows: list[dict] = []
    text_len = _fn("user32", "GetWindowTextLengthW")
    get_text = _fn("user32", "GetWindowTextW")
    visible = _fn("user32", "IsWindowVisible")
    owner = _fn("user32", "GetWindowThreadProcessId")

    def callback(hwnd, _lparam):
        try:
            if not visible(hwnd):
                return True
            length = text_len(hwnd)
            if length <= 0:
                return True
            buf = ctypes.create_unicode_buffer(length + 1)
            get_text(hwnd, buf, length + 1)
            title = buf.value.strip()
            if title:
                pid = wintypes.DWORD(0)
                owner(hwnd, ctypes.byref(pid))
                rows.append({"title": title, "pid": int(pid.value), "hwnd": int(hwnd or 0)})
        except Exception:  # noqa: S110 - an exception must not cross the C callback
            pass
        return True

    proc = _WNDENUMPROC(callback)
    if not _fn("user32", "EnumWindows")(proc, 0):
        raise _fail("EnumWindows")
    return rows


# ---------------------------------------------------------------- files


def _directory(name: str) -> str:
    get = _fn("kernel32", name)
    size = 260
    while True:
        buf = ctypes.create_unicode_buffer(size)
        n = get(buf, size)
        if n == 0:
            raise _fail(name)
        if n < size:
            return buf.value
        size = n + 1


def system_directory() -> str:
    """The System32 directory (GetSystemDirectoryW)."""
    return _directory("GetSystemDirectoryW")


def windows_directory() -> str:
    """The shared Windows directory (GetSystemWindowsDirectoryW)."""
    return _directory("GetSystemWindowsDirectoryW")


def final_path_of_fd(fd: int) -> str:
    """The resolved path of an open file descriptor (GetFinalPathNameByHandleW)."""
    import msvcrt

    handle = msvcrt.get_osfhandle(fd)
    get = _fn("kernel32", "GetFinalPathNameByHandleW")
    size = 512
    while True:
        buf = ctypes.create_unicode_buffer(size)
        n = get(handle, buf, size, 0)
        if n == 0:
            raise _fail("GetFinalPathNameByHandleW")
        if n < size:
            return core.strip_extended_prefix(buf.value)
        size = n + 1
