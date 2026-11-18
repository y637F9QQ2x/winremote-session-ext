import pytest

from winremote_session_ext import core


def test_integrity_names():
    assert core.integrity_name(0x1000) == "low"
    assert core.integrity_name(0x2000) == "medium"
    assert core.integrity_name(0x3000) == "high"
    assert core.integrity_name(0x4000) == "system"
    assert core.integrity_name(0x2010) == "medium+0x2010"


def test_enum_names():
    assert core.elevation_type_name(3) == "limited"
    assert core.elevation_type_name(9) == "unknown(9)"
    assert core.wts_state_name(0) == "active"
    assert core.wts_state_name(4) == "disconnected"
    assert core.wts_state_name(42) == "unknown(42)"


def test_is_interactive():
    assert core.is_interactive(1, "WinSta0", True)
    assert not core.is_interactive(0, "WinSta0", True)
    assert not core.is_interactive(2, "Service-0x0-3e7$", False)
    assert not core.is_interactive(2, "WinSta0", False)
    assert not core.is_interactive(2, None, True)


def test_administrators_state():
    assert core.administrators_state(None) == "absent"
    assert core.administrators_state(0x10) == "deny-only"
    assert core.administrators_state(0x7) == "enabled"
    assert core.administrators_state(0x0) == "present-disabled"


def test_needs_tscon():
    assert core.needs_tscon(core.WTS_DISCONNECTED, False)
    assert not core.needs_tscon(core.WTS_ACTIVE, False)
    assert core.needs_tscon(core.WTS_ACTIVE, True)
    with pytest.raises(RuntimeError):
        core.needs_tscon(None, False)


def test_match_windows():
    windows = [
        {"title": "Settings"},
        {"title": "User Account Control"},
        {"title": "Untitled - Notepad"},
    ]
    assert [w["title"] for w in core.match_windows(windows, "notepad")] == ["Untitled - Notepad"]
    assert core.match_windows(windows, "settings", exact=True) == [{"title": "Settings"}]
    assert core.match_windows(windows, "Sett", exact=True) == []


def test_strip_extended_prefix():
    assert core.strip_extended_prefix("\\\\?\\C:\\r\\a.txt") == "C:\\r\\a.txt"
    assert core.strip_extended_prefix("\\\\?\\UNC\\srv\\share\\a") == "\\\\srv\\share\\a"
    assert core.strip_extended_prefix("C:\\r") == "C:\\r"


def test_is_within():
    assert core.is_within("C:\\Results\\a.txt", "C:\\results")
    assert core.is_within("C:\\Results", "C:\\Results\\")
    assert core.is_within("\\\\?\\C:\\Results\\x\\y", "C:\\Results")
    assert not core.is_within("C:\\Results-other\\a.txt", "C:\\Results")
    assert not core.is_within("C:\\a.txt", "C:\\Results")
    assert not core.is_within("D:\\Results\\a.txt", "C:\\Results")


def test_clamp_and_clip():
    assert core.clamp(500, 0, 120) == 120
    assert core.clamp(-1, 0, 120) == 0
    assert core.clip("abcdef", 3) == "abc..."
    assert core.clip("abc", 3) == "abc"
