"""Consistency checks across the files of this repository (no imports of upstream)."""

import re
import tomllib
from pathlib import Path

from winremote_session_ext import policy

ROOT = Path(__file__).resolve().parents[1]


def _pyproject():
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]


def _requirement_lines(name):
    lines = (ROOT / name).read_text(encoding="utf-8").splitlines()
    return [line.strip() for line in lines if line.strip() and not line.startswith("#")]


def test_client_script_reports_the_package_version():
    script = (ROOT / "scripts" / "Invoke-WinRemoteTool.ps1").read_text(encoding="utf-8")
    found = re.findall(r"name = 'Invoke-WinRemoteTool'; version = '([^']+)'", script)
    assert found == [_pyproject()["version"]]


def test_every_upstream_pin_names_the_supported_release():
    pin = f"winremote-mcp=={policy.SUPPORTED_UPSTREAM}"
    assert pin in _pyproject()["dependencies"]
    assert _requirement_lines("requirements.txt") == [pin]
    assert pin in _requirement_lines("constraints.txt")


def test_constraints_pin_exact_versions():
    for line in _requirement_lines("constraints.txt"):
        assert re.fullmatch(r"[a-z0-9][a-z0-9.-]*==[0-9][0-9A-Za-z.]*", line), line
