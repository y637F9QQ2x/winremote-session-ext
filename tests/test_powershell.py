"""Runs the PowerShell checks in tests/ps (offline):

- check_scripts.ps1: AST parse of every script, and the pure helper functions;
- check_script_runs.ps1: the scripts' main bodies, with a stub server process
  for Start-SessionServer.ps1 and a replaced Invoke-WebRequest for
  Invoke-WinRemoteTool.ps1 (PowerShell 7 only).
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

PS_DIR = Path(__file__).parent / "ps"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
@pytest.mark.parametrize("check", ["check_scripts.ps1", "check_script_runs.ps1"])
@pytest.mark.parametrize("shell", ["pwsh", "powershell"])
def test_powershell_checks(shell, check):
    exe = shutil.which(shell)
    if exe is None:
        pytest.skip(f"{shell} not found")
    env = dict(os.environ, PYTHON_FOR_TESTS=sys.executable)
    if shell == "powershell":
        # PowerShell 7 puts its own module folders first in PSModulePath, and a
        # pytest started from pwsh passes that on. Windows PowerShell 5.1 then
        # fails to load Microsoft.PowerShell.Security (Get-Acl). Without the
        # variable, 5.1 builds its default module path. The keys of os.environ
        # are upper case on Windows, so the name is compared without case.
        env = {k: v for k, v in env.items() if k.upper() != "PSMODULEPATH"}
    result = subprocess.run(
        [
            exe,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(PS_DIR / check),
        ],
        capture_output=True,
        text=True,
        timeout=180,
        env=env,
    )
    assert result.returncode == 0, result.stderr + result.stdout
