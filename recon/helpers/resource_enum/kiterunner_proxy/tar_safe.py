"""Fail-closed extraction for Kiterunner source and wordlist archives.

Only regular files and directories are admitted. Both archives need no links;
refusing all links also prevents chained archive symlink/hardlink escapes on
Python versions without tarfile's data filter.
"""
from __future__ import annotations
import tarfile
from pathlib import Path, PurePosixPath

class UnsafeArchiveError(ValueError):
    """The archive is outside the supported regular-file format."""

def _validate_member(root: Path, member: tarfile.TarInfo) -> None:
    if not (member.isfile() or member.isdir()):
        raise UnsafeArchiveError(f"unsupported archive member: {member.name!r}")
    name = member.name
    path = PurePosixPath(name)
    if not name or path.is_absolute() or ".." in path.parts or "\\" in name:
        raise UnsafeArchiveError(f"unsafe archive path: {name!r}")
    target = root.joinpath(*path.parts).resolve()
    if target != root and root not in target.parents:
        raise UnsafeArchiveError(f"unsafe archive path: {name!r}")

def safe_extract_tar(tar: tarfile.TarFile, dest: str | Path) -> None:
    root = Path(dest)
    root.mkdir(parents=True, exist_ok=True)
    root = root.resolve()
    members = tar.getmembers()
    for member in members:
        _validate_member(root, member)
    for member in members:
        # Revalidate against filesystem state as well as archive metadata.
        _validate_member(root, member)
        tar.extract(member, path=str(root), filter="data")
