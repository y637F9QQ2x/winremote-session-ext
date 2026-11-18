"""Read-only Windows API calls against the test process itself."""

import os
import sys
import tempfile

import pytest

from winremote_session_ext import winapi

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows only")


def test_token_summary_shape():
    report = winapi.token_summary()
    assert report["sid"].startswith("S-1-")
    assert report["integrity_level"] in {"low", "medium", "medium-plus", "high", "system"}
    assert report["integrity_rid"].startswith("0x")
    assert isinstance(report["elevated"], bool)
    assert report["elevation_type"] in {"default", "full", "limited"}
    assert report["administrators_group"] in {"absent", "enabled", "deny-only", "present-disabled"}


def test_own_session_is_listed():
    own = winapi.own_session_id()
    rows = winapi.list_sessions()
    assert own in {row["session_id"] for row in rows}
    assert all(set(row) == {"session_id", "station", "state", "user", "domain"} for row in rows)
    assert winapi.session_state(own) is not None


def test_window_station_and_desktop_are_named():
    station, visible = winapi.window_station()
    assert station
    assert isinstance(visible, bool)
    assert winapi.thread_desktop()


def test_visible_windows_shape():
    for row in winapi.visible_windows():
        assert set(row) == {"title", "pid", "hwnd"}
        assert row["title"]


def test_system_directories():
    system = winapi.system_directory()
    windows = winapi.windows_directory()
    assert os.path.isdir(system) and os.path.isdir(windows)
    assert os.path.normcase(os.path.dirname(system)) == os.path.normcase(windows)
    assert os.path.basename(system).lower() == "system32"


def test_final_path_of_fd_matches_realpath():
    fd, path = tempfile.mkstemp()
    try:
        final = winapi.final_path_of_fd(fd)
        assert os.path.normcase(final) == os.path.normcase(os.path.realpath(path))
    finally:
        os.close(fd)
        os.remove(path)
