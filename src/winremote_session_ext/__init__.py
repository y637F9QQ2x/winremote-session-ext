"""Session-aware tools and HTTP hardening for winremote-mcp."""

from importlib import metadata

try:
    # The version is defined once, in pyproject.toml.
    __version__ = metadata.version("winremote-session-ext")
except metadata.PackageNotFoundError:  # a source tree that is not installed
    __version__ = "0+unknown"
