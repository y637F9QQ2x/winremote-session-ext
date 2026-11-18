import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import winremote_session_ext

SRC = Path(__file__).resolve().parents[1] / "src"


def pytest_configure(config):
    # The tests must exercise this tree, not a copy installed in site-packages.
    package = Path(winremote_session_ext.__file__).resolve()
    if SRC not in package.parents:
        raise pytest.UsageError(f"winremote_session_ext was imported from {package}, not {SRC}")


@pytest.fixture(scope="session")
def upstream():
    """winremote-mcp imported in-process the way the launcher imports it, with the
    extension installed.

    mcp.run is replaced by a recorder BEFORE install(), so no test can start
    a server or open a socket. Skipped when winremote-mcp is not installed.
    """
    if sys.platform != "win32" or importlib.util.find_spec("winremote") is None:
        pytest.skip("winremote-mcp is not installed")
    from winremote_session_ext import extension, launcher

    W, tiers, auth, security = launcher.import_upstream()
    calls = []

    def recorder(*args, **kwargs):
        calls.append(kwargs)

    W.mcp.run = recorder
    upstream_tools = set(W._get_registered_tools())
    names = extension.install(W, tiers, auth, security)
    return SimpleNamespace(
        W=W,
        tiers=tiers,
        auth=auth,
        security=security,
        calls=calls,
        names=names,
        upstream_tools=upstream_tools,
        extension=extension,
    )
