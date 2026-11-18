"""Command line entry point: `python -m winremote_session_ext [upstream options]`.

It checks the arguments, imports winremote-mcp without letting it read .env
files, installs the extension and then hands the same arguments to
upstream's own click CLI.

Exit codes: 0 normal end, 1 a refused configuration (click.ClickException,
for example a refused HTTP launch), 2 a refused option or a usage error,
3 winremote-mcp is missing or not the supported release.
"""

from __future__ import annotations

import sys

from . import extension, policy

PROG = "winremote-session-ext"


def _no_dotenv(*_args, **_kwargs) -> bool:
    return False


def disable_dotenv() -> None:
    """Make python-dotenv's load_dotenv() a no-op for this process.

    Upstream runs `from dotenv import load_dotenv` and `load_dotenv()` when it is
    imported, and python-dotenv then looks for a .env file in the folder of the
    upstream package and in every folder above it. The key and the
    WINREMOTE_EXT_* settings must come only from the real environment, so the
    replacement happens before upstream is imported.
    """
    import dotenv

    dotenv.load_dotenv = _no_dotenv


def import_upstream():
    disable_dotenv()
    import winremote.__main__ as W
    from winremote import auth, security, tiers

    return W, tiers, auth, security


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    errors = policy.check_argv(args)
    if errors:
        for error in errors:
            sys.stderr.write(f"{PROG}: {error}\n")
        return 2
    try:
        W, tiers, auth, security = import_upstream()
    except Exception as exc:
        sys.stderr.write(
            f"{PROG}: cannot import winremote-mcp ({exc}); "
            "install it with: pip install -r requirements.txt\n"
        )
        return 3
    try:
        extension.install(W, tiers, auth, security)
    except extension.CompatibilityError as exc:
        sys.stderr.write(f"{PROG}: not starting, upstream is not compatible: {exc}\n")
        return 3

    import click

    # standalone_mode=False: click raises instead of calling sys.exit, so the
    # exit code is decided here and main() always returns one.
    try:
        result = W.cli.main(args=args, prog_name=PROG, standalone_mode=False)
    except click.ClickException as exc:
        exc.show()
        return exc.exit_code
    except click.Abort:
        sys.stderr.write("Aborted!\n")
        return 1
    return result if isinstance(result, int) else 0
