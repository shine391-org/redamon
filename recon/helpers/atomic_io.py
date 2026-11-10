"""Atomic, explicitly-failing JSON artifact writes.

The recon artifact is written dozens of times per run, once per phase, and read
by the orchestrator, the export endpoint and the GVM scanner. A plain
``open(path, "w")`` truncates the file first: a crash, a kill, or a full disk
between the truncate and the last write leaves a file that is shorter than it
was, or empty, and every downstream reader then sees a run that produced
nothing. That is indistinguishable from a clean scan that found nothing.

Writing to a sibling temporary file and ``os.replace``-ing it into place makes
the swap atomic on the same filesystem: a reader sees either the previous
complete artifact or the new one, never a half-written one. A failure raises —
an artifact that cannot be written is an explicit failure, not a silent one.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Optional


class ArtifactWriteError(RuntimeError):
    """The artifact could not be written. Raised, never swallowed."""


class ArtifactTooLarge(RuntimeError):
    """The serialized payload exceeds the caller's bound."""


def serialize_json(data: Any, *, indent: Optional[int] = 2) -> str:
    """The exact bytes every artifact writer uses, so a roundtrip is comparable."""
    return json.dumps(data, indent=indent, ensure_ascii=True, default=str)


def atomic_write_text(path, text: str, *, max_bytes: Optional[int] = None) -> None:
    """Write ``text`` to ``path`` atomically, or raise.

    ``max_bytes`` bounds the payload before anything touches the destination.
    Refusing an oversized artifact up front is better than writing half of it
    and failing on the last buffer flush.
    """
    destination = Path(path)
    if max_bytes is not None:
        size = len(text.encode("utf-8"))
        if size > max_bytes:
            raise ArtifactTooLarge(
                f"{destination.name}: {size} bytes exceeds the {max_bytes} byte bound")
    directory = destination.parent
    handle = None
    tmp_name = None
    try:
        fd, tmp_name = tempfile.mkstemp(
            prefix=f".{destination.name}.", suffix=".tmp", dir=str(directory))
        handle = os.fdopen(fd, "w", encoding="utf-8")
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
        handle.close()
        handle = None
        os.replace(tmp_name, destination)
        tmp_name = None
    except OSError as exc:
        raise ArtifactWriteError(f"{destination}: {exc}") from exc
    finally:
        if handle is not None:
            try:
                handle.close()
            except OSError:
                pass
        if tmp_name is not None:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass


def atomic_write_json(path, data: Any, *, indent: Optional[int] = 2,
                      max_bytes: Optional[int] = None) -> None:
    """``atomic_write_text`` for a JSON-serializable payload."""
    atomic_write_text(path, serialize_json(data, indent=indent), max_bytes=max_bytes)


def atomic_write_with_lock(path, data: Any, lock, *, indent: Optional[int] = 2,
                           max_bytes: Optional[int] = None) -> None:
    """``atomic_write_json`` under an existing lock, so a read-modify-write stays whole."""
    with lock:
        atomic_write_json(path, data, indent=indent, max_bytes=max_bytes)
