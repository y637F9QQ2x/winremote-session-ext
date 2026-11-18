"""Console attach and WaitForWindow logic, with the Windows calls, tscon and the
clock replaced by fakes. Nothing here runs tscon or reads real session state."""

import os
import subprocess
from types import SimpleNamespace

import pytest

from winremote_session_ext import core, policy, tools

SYSTEM32 = "C:\\Windows\\System32"


class ToolError(Exception):
    pass


class FakeWindows:
    """own_session_id, session_state, the System32 lookup, subprocess.run and time.sleep."""

    def __init__(self, monkeypatch, own=2, states=(core.WTS_DISCONNECTED,), **tscon):
        self.own = own
        self.states = list(states)
        self.tscon = tscon
        self.runs = []
        self.sleeps = []
        monkeypatch.setattr(tools.winapi, "own_session_id", lambda: self.own)
        monkeypatch.setattr(tools.winapi, "session_state", self.session_state)
        monkeypatch.setattr(tools.winapi, "system_directory", lambda: SYSTEM32)
        monkeypatch.setattr(tools, "struct", SimpleNamespace(calcsize=lambda fmt: 8))
        monkeypatch.setattr(
            tools,
            "subprocess",
            SimpleNamespace(run=self.run, TimeoutExpired=subprocess.TimeoutExpired),
        )
        monkeypatch.setattr(tools, "time", SimpleNamespace(sleep=self.sleeps.append))

    def session_state(self, session_id):
        assert session_id == self.own
        if isinstance(self.states[0], Exception):
            raise self.states[0]
        return self.states.pop(0) if len(self.states) > 1 else self.states[0]

    def run(self, argv, **kwargs):
        self.runs.append((argv, kwargs))
        if self.tscon.get("timeout"):
            raise subprocess.TimeoutExpired(argv, kwargs["timeout"])
        return SimpleNamespace(
            returncode=self.tscon.get("returncode", 0),
            stdout=self.tscon.get("stdout", ""),
            stderr=self.tscon.get("stderr", ""),
        )


def test_session_zero_is_refused_without_tscon(monkeypatch):
    fake = FakeWindows(monkeypatch, own=0)
    assert "session 0" in tools.reconnect(False)
    assert fake.runs == []


def test_active_session_needs_nothing(monkeypatch):
    fake = FakeWindows(monkeypatch, states=[core.WTS_ACTIVE])
    assert tools.attach_to_console(force=False) == "none"
    assert fake.runs == []


def test_disconnected_session_runs_tscon_for_its_own_id(monkeypatch):
    fake = FakeWindows(monkeypatch, own=2, states=[core.WTS_DISCONNECTED, core.WTS_ACTIVE])
    assert tools.attach_to_console(force=False) == "tscon"
    [(argv, kwargs)] = fake.runs
    assert argv == [os.path.join(SYSTEM32, "tscon.exe"), "2", "/dest:console"]
    assert kwargs["timeout"] == tools.TSCON_TIMEOUT_S
    assert kwargs["capture_output"] is True
    assert fake.sleeps == []


def test_force_runs_tscon_for_an_active_session(monkeypatch):
    fake = FakeWindows(monkeypatch, states=[core.WTS_ACTIVE])
    assert tools.reconnect(True) is None
    assert len(fake.runs) == 1


def test_unreadable_state_is_an_error_without_tscon(monkeypatch):
    fake = FakeWindows(monkeypatch, states=[None])
    assert tools.reconnect(False) == "could not read this session's connect state"
    assert fake.runs == []


def test_tscon_failure_message_is_returned(monkeypatch):
    FakeWindows(monkeypatch, returncode=1, stderr="Access is denied.\n")
    assert tools.reconnect(False) == "tscon failed: Access is denied."


def test_tscon_timeout_is_reported(monkeypatch):
    FakeWindows(monkeypatch, timeout=True)
    assert tools.reconnect(False) == "tscon timed out"


def test_session_that_does_not_become_active_is_an_error(monkeypatch):
    fake = FakeWindows(monkeypatch, states=[core.WTS_DISCONNECTED])
    message = tools.reconnect(False)
    assert message == "tscon exited with code 0, but session 2 is disconnected, not active"
    assert fake.sleeps == [tools.ATTACH_POLL_S] * (tools.ATTACH_POLLS - 1)


# ---------------------------------------------------------------- upstream's callers


def test_snapshot_retry_does_not_run_tscon(monkeypatch):
    # Snapshot and AnnotatedSnapshot call the function with no argument.
    monkeypatch.delenv(policy.AUTO_ATTACH_ENV, raising=False)
    fake = FakeWindows(monkeypatch, states=[core.WTS_DISCONNECTED])
    replacement = tools.make_session_reconnect(ToolError)
    with pytest.raises(ToolError) as info:
        replacement()
    assert "ReconnectSession" in str(info.value)
    assert fake.runs == []


def test_snapshot_retry_on_a_connected_session_reports_the_original_error(monkeypatch):
    monkeypatch.delenv(policy.AUTO_ATTACH_ENV, raising=False)
    fake = FakeWindows(monkeypatch, states=[core.WTS_ACTIVE])
    result = tools.make_session_reconnect(ToolError)()
    # A string (not None) makes upstream report its own screen grab error, without a retry.
    assert isinstance(result, str)
    assert fake.runs == []


def test_snapshot_retry_with_unreadable_state_returns_an_error(monkeypatch):
    monkeypatch.delenv(policy.AUTO_ATTACH_ENV, raising=False)
    FakeWindows(monkeypatch, states=[OSError("no WTS")])
    assert "no WTS" in tools.make_session_reconnect(ToolError)()


def test_snapshot_retry_attaches_only_with_the_opt_in(monkeypatch):
    monkeypatch.setenv(policy.AUTO_ATTACH_ENV, "1")
    fake = FakeWindows(monkeypatch, states=[core.WTS_DISCONNECTED, core.WTS_ACTIVE])
    assert tools.make_session_reconnect(ToolError)() is None
    assert len(fake.runs) == 1


@pytest.mark.parametrize("force", [False, True])
def test_reconnect_session_calls_attach(monkeypatch, force):
    # ReconnectSession always passes force=..., also when it is False.
    monkeypatch.delenv(policy.AUTO_ATTACH_ENV, raising=False)
    fake = FakeWindows(monkeypatch, states=[core.WTS_DISCONNECTED, core.WTS_ACTIVE])
    assert tools.make_session_reconnect(ToolError)(force=force) is None
    assert len(fake.runs) == 1


# ---------------------------------------------------------------- tscon path


def test_tscon_path_for_64_bit_python(monkeypatch):
    monkeypatch.setattr(tools.winapi, "system_directory", lambda: SYSTEM32)
    monkeypatch.setattr(tools, "struct", SimpleNamespace(calcsize=lambda fmt: 8))
    assert tools.tscon_path() == os.path.join(SYSTEM32, "tscon.exe")


def test_tscon_path_for_32_bit_python_uses_sysnative_when_present(monkeypatch, tmp_path):
    (tmp_path / "Sysnative").mkdir()
    monkeypatch.setattr(tools.winapi, "system_directory", lambda: SYSTEM32)
    monkeypatch.setattr(tools.winapi, "windows_directory", lambda: str(tmp_path))
    monkeypatch.setattr(tools, "struct", SimpleNamespace(calcsize=lambda fmt: 4))
    assert tools.tscon_path() == str(tmp_path / "Sysnative" / "tscon.exe")
    (tmp_path / "Sysnative").rmdir()
    assert tools.tscon_path() == os.path.join(SYSTEM32, "tscon.exe")


# ---------------------------------------------------------------- WaitForWindow


class Clock:
    def __init__(self):
        self.now = 100.0
        self.sleeps = []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


def wait(monkeypatch, timeout, poll, titles_per_poll):
    clock = Clock()
    batches = list(titles_per_poll)
    monkeypatch.setattr(tools, "time", clock)
    monkeypatch.setattr(
        tools.winapi,
        "visible_windows",
        lambda: [{"title": t, "pid": 1, "hwnd": 1} for t in (batches.pop(0) if batches else [])],
    )
    return tools.wait_for_window("Notepad", timeout, poll, False), clock


def test_wait_ends_at_the_deadline_not_one_poll_later(monkeypatch):
    report, clock = wait(monkeypatch, 1.0, 5.0, [])
    assert report["found"] is False and report["polls"] == 2
    assert clock.sleeps == [1.0]


def test_wait_cuts_the_last_sleep(monkeypatch):
    report, clock = wait(monkeypatch, 1.25, 0.5, [])
    assert report["found"] is False and report["elapsed_s"] == 1.25
    assert clock.sleeps == [0.5, 0.5, 0.25]


def test_wait_returns_the_match(monkeypatch):
    report, clock = wait(monkeypatch, 10.0, 0.5, [["Settings"], [], ["Untitled - Notepad"]])
    assert report["found"] is True and report["polls"] == 3
    assert report["matches"][0]["title"] == "Untitled - Notepad"
    assert clock.sleeps == [0.5, 0.5]
