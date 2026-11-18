"""ReadResultFile confinement, against files in a pytest temporary directory."""

import hashlib
import os
import sys

import pytest

from winremote_session_ext.tools import read_result_file

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows only")


@pytest.fixture
def layout(tmp_path):
    root = tmp_path / "results"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (root / "marker.txt").write_bytes(b"done\n")
    (root / "sub").mkdir()
    (root / "sub" / "big.txt").write_bytes(b"x" * 100)
    (outside / "secret.txt").write_bytes(b"secret")
    return root, outside


def test_reads_relative_path_with_hash(layout):
    root, _ = layout
    report = read_result_file("marker.txt", 65536, "utf-8", str(root))
    assert report["content"] == "done\n"
    assert report["truncated"] is False
    assert report["size"] == 5
    assert report["sha256"] == hashlib.sha256(b"done\n").hexdigest()


def test_truncates_and_omits_hash(layout):
    root, _ = layout
    report = read_result_file("sub\\big.txt", 10, "utf-8", str(root))
    assert report["content"] == "x" * 10
    assert report["truncated"] is True
    assert "sha256" not in report


def test_refuses_parent_traversal(layout):
    root, _ = layout
    with pytest.raises(PermissionError):
        read_result_file("..\\outside\\secret.txt", 100, "utf-8", str(root))


def test_refuses_absolute_path_outside(layout):
    root, outside = layout
    with pytest.raises(PermissionError):
        read_result_file(str(outside / "secret.txt"), 100, "utf-8", str(root))


def _resolve_only_the_root(monkeypatch, root):
    """Replace os.path.realpath with a version that raises for every path but the root.

    realpath() opens the path it resolves; for a UNC path that is an SMB
    connection. With this stand-in, code that resolved the requested path would
    fail the test instead of reaching the network.
    """
    real = os.path.realpath

    def root_only(path, *args, **kwargs):
        if path != str(root):
            raise AssertionError(f"realpath() was called with {path!r}")
        return real(path, *args, **kwargs)

    monkeypatch.setattr(os.path, "realpath", root_only)


@pytest.mark.parametrize(
    "path",
    [
        "\\\\example.invalid\\share\\a.txt",
        "//example.invalid/share/a.txt",
        "\\\\?\\UNC\\example.invalid\\share\\a.txt",
        "\\\\.\\pipe\\example",
        "\\a.txt",
        "..\\outside\\secret.txt",
    ],
    ids=["unc", "unc-slashes", "unc-extended", "pipe", "root-relative", "parent"],
)
def test_refuses_paths_outside_before_resolving_them(layout, monkeypatch, path):
    root, _ = layout
    _resolve_only_the_root(monkeypatch, root)
    with pytest.raises(PermissionError, match="outside the result directory"):
        read_result_file(path, 100, "utf-8", str(root))


def test_refuses_a_drive_relative_path_on_another_drive(layout, monkeypatch):
    root, _ = layout
    other = "E:" if os.path.splitdrive(str(root))[0].upper() == "D:" else "D:"
    _resolve_only_the_root(monkeypatch, root)
    with pytest.raises(PermissionError, match="outside the result directory"):
        read_result_file(other + "a.txt", 100, "utf-8", str(root))


def test_refuses_junction_escape(layout):
    _winapi = pytest.importorskip("_winapi")
    root, outside = layout
    _winapi.CreateJunction(str(outside), str(root / "link"))
    with pytest.raises(PermissionError):
        read_result_file("link\\secret.txt", 100, "utf-8", str(root))


def test_refuses_hard_link_to_a_file_outside(layout):
    root, outside = layout
    os.link(outside / "secret.txt", root / "linked.txt")
    with pytest.raises(PermissionError, match="hard link"):
        read_result_file("linked.txt", 100, "utf-8", str(root))


def test_refuses_directory(layout):
    root, _ = layout
    with pytest.raises(OSError):
        read_result_file("sub", 100, "utf-8", str(root))


def test_requires_configured_root():
    with pytest.raises(ValueError):
        read_result_file("marker.txt", 100, "utf-8", None)


def test_rejects_bad_input(layout):
    root, _ = layout
    with pytest.raises(ValueError):
        read_result_file("", 100, "utf-8", str(root))
    with pytest.raises(ValueError):
        read_result_file("a\x00b", 100, "utf-8", str(root))
    with pytest.raises(LookupError):
        read_result_file("marker.txt", 100, "no-such-codec", str(root))


def test_missing_file(layout):
    root, _ = layout
    with pytest.raises(FileNotFoundError):
        read_result_file("absent.txt", 100, "utf-8", str(root))
