"""Pure helpers used by the tools. No Windows API calls here."""

from __future__ import annotations

import ntpath

# Mandatory integrity level RIDs (winnt.h SECURITY_MANDATORY_*_RID).
_INTEGRITY_NAMES = {
    0x0000: "untrusted",
    0x1000: "low",
    0x2000: "medium",
    0x2100: "medium-plus",
    0x3000: "high",
    0x4000: "system",
    0x5000: "protected-process",
}

# TOKEN_ELEVATION_TYPE (winnt.h).
_ELEVATION_TYPES = {1: "default", 2: "full", 3: "limited"}

# WTS_CONNECTSTATE_CLASS (wtsapi32.h).
_WTS_STATES = {
    0: "active",
    1: "connected",
    2: "connect-query",
    3: "shadow",
    4: "disconnected",
    5: "idle",
    6: "listen",
    7: "reset",
    8: "down",
    9: "init",
}

WTS_ACTIVE = 0
WTS_DISCONNECTED = 4
NO_CONSOLE_SESSION = 0xFFFFFFFF


def integrity_name(rid: int) -> str:
    if rid in _INTEGRITY_NAMES:
        return _INTEGRITY_NAMES[rid]
    lower = [r for r in _INTEGRITY_NAMES if r <= rid]
    base = _INTEGRITY_NAMES[max(lower)] if lower else "untrusted"
    return f"{base}+0x{rid:04x}"


def elevation_type_name(value: int) -> str:
    return _ELEVATION_TYPES.get(value, f"unknown({value})")


def wts_state_name(value: int) -> str:
    return _WTS_STATES.get(value, f"unknown({value})")


def is_interactive(session_id: int, window_station: str | None, station_visible: bool) -> bool:
    """True when the process can own visible windows on a user desktop.

    Session 0 never has one. Elsewhere the process must sit in the visible
    interactive window station, WinSta0.
    """
    return session_id != 0 and (window_station or "").lower() == "winsta0" and bool(station_visible)


def needs_tscon(state: int | None, force: bool) -> bool:
    """tscon runs only for a disconnected session, unless forced."""
    if force:
        return True
    if state is None:
        raise RuntimeError("could not read this session's connect state")
    return state == WTS_DISCONNECTED


def administrators_state(attributes: int | None) -> str:
    """Describe the BUILTIN\\Administrators entry of a token's groups."""
    if attributes is None:
        return "absent"
    if attributes & 0x10:  # SE_GROUP_USE_FOR_DENY_ONLY
        return "deny-only"
    if attributes & 0x4:  # SE_GROUP_ENABLED
        return "enabled"
    return "present-disabled"


def clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def match_windows(windows: list[dict], needle: str, exact: bool = False) -> list[dict]:
    """Filter window dicts by title, ignoring case."""
    wanted = needle.casefold()
    hits = []
    for window in windows:
        title = window.get("title", "").casefold()
        if (title == wanted) if exact else (wanted in title):
            hits.append(window)
    return hits


def strip_extended_prefix(path: str) -> str:
    r"""Turn '\\?\C:\x' into 'C:\x' and '\\?\UNC\s\x' into '\\s\x'."""
    if path.startswith("\\\\?\\UNC\\"):
        return "\\\\" + path[8:]
    if path.startswith("\\\\?\\"):
        return path[4:]
    return path


def is_within(child: str, parent: str) -> bool:
    """True if child equals parent or lies below it (Windows path rules)."""
    child_n = ntpath.normcase(strip_extended_prefix(child))
    parent_n = ntpath.normcase(strip_extended_prefix(parent))
    try:
        return ntpath.commonpath([child_n, parent_n]) == ntpath.commonpath([parent_n])
    except ValueError:
        return False


def clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit] + "..."
